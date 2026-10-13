use std::io;
use std::net::{IpAddr, SocketAddr};
use std::os::fd::{AsRawFd, RawFd};

use socket2::SockRef;
use tokio::net::{TcpListener, TcpSocket, TcpStream};
use tracing::{debug, warn};

use crate::session::ResolvedAuth;

/// Opens an outbound TCP connection to `remote`, optionally bound to
/// `source` (the peer-group's configured transport source address) and, on
/// Linux, scoped into `vrf` via `SO_BINDTODEVICE` — the same mechanism
/// `nos-ribd`'s driver uses at the kernel level, applied here at the socket
/// level since `nos-bgpd` never touches `rtnetlink` directly. `auth`, if
/// set, is installed on the socket before `connect()` so the TCP handshake
/// itself is already signed/authenticated (see `apply_auth`).
pub async fn connect(
    remote: SocketAddr,
    source: Option<IpAddr>,
    vrf: Option<&str>,
    auth: Option<&ResolvedAuth>,
    max_hops: Option<u8>,
) -> io::Result<TcpStream> {
    let socket = new_socket(remote.is_ipv4())?;
    if let Some(vrf) = vrf {
        bind_device(&socket, vrf)?;
    }
    if let Some(auth) = auth {
        apply_auth(socket.as_raw_fd(), remote.ip(), auth, false)?;
    }
    if let Some(hops) = max_hops {
        apply_max_hops(socket.as_raw_fd(), remote.ip(), hops)?;
    }
    if let Some(source) = source {
        if source.is_ipv4() == remote.is_ipv4() {
            socket.bind(SocketAddr::new(source, 0))?;
        } else {
            warn!(
                %source, %remote,
                "peer-group source-address family doesn't match remote address, ignoring"
            );
        }
    }
    socket.connect(remote).await
}

/// Enables RFC 5082 GTSM on a connect socket or an accepted stream (a shared
/// listener can't carry it: the minimum TTL is per socket, not per peer).
pub fn apply_max_hops(fd: RawFd, peer: IpAddr, hops: u8) -> io::Result<()> {
    nos_tcp_auth::set_max_hops(fd, peer.is_ipv6(), hops)?;
    debug!(%peer, hops, "max hops applied");
    Ok(())
}

/// Installs `auth` on `fd`, scoped to `peer` — used both for an outbound
/// socket (before `connect()`) and a shared passive listener (keyed by the
/// peer's address, since the listener serves every configured peer; see
/// `session::SessionManager::sync_listener_auth`/`spawn_listeners`). Adding
/// a TCP-AO key with a `(send_id, recv_id)` that already exists on `fd`
/// replaces it in place, so this is also how a changed key gets applied.
///
/// `on_listener` must be `true` for the shared listening socket: the kernel
/// rejects `TCP_AO_ADD_KEY`'s `set_current`/`set_rnext` bits with `EINVAL`
/// on a socket in `LISTEN` state (found by running `nos-e2e ao` against a
/// real kernel — there is no way to discover this from the header alone).
/// This is harmless to drop there: those bits designate the key actively
/// signing/rolling on *one* connection, a concept a listener itself has
/// none of; the kernel still matches an accepted connection's key from the
/// wire's `KeyID`/`RNextKeyID` against every key installed here, current or not.
pub fn apply_auth(
    fd: RawFd,
    peer: IpAddr,
    auth: &ResolvedAuth,
    on_listener: bool,
) -> io::Result<()> {
    match auth {
        ResolvedAuth::Md5(password) => nos_tcp_auth::set_md5_key(fd, peer, password.as_bytes()),
        ResolvedAuth::Ao(keys) => {
            let rnext = crate::session::ao_rnext(keys).map(|k| k.send_id);
            for key in keys {
                let key = nos_tcp_auth::AoKey {
                    set_current: key.set_current && !on_listener,
                    // Always advertise one RNextKeyID on a connection: the
                    // flagged key, else the current one (never "whichever
                    // the kernel saw first").
                    set_rnext: !on_listener && Some(key.send_id) == rnext,
                    ..key.clone()
                };
                nos_tcp_auth::add_ao_key(fd, peer, &key)?;
            }
            Ok(())
        }
    }
}

/// Applies an in-place TCP-AO key-list change to `fd`: adds first, then (on a
/// live connection) moves rnext, then deletes — so a key being retired is
/// never the rnext key when it goes, and one being introduced exists before
/// it is advertised. A key the peer is still signing with (`EBUSY`) surfaces
/// as the error. A listener has no current/rnext key, so `live = false`
/// skips the rnext step.
pub fn apply_ao_delta(
    fd: RawFd,
    peer: IpAddr,
    delta: &crate::session::AoDelta,
    live: bool,
) -> io::Result<()> {
    for key in &delta.add {
        let key = nos_tcp_auth::AoKey {
            set_current: false,
            set_rnext: false,
            ..key.clone()
        };
        nos_tcp_auth::add_ao_key(fd, peer, &key)?;
    }
    if live {
        nos_tcp_auth::set_ao_rnext(fd, delta.rnext_recv_id)?;
    }
    for &(send_id, recv_id) in &delta.remove {
        nos_tcp_auth::delete_ao_key(fd, peer, send_id, recv_id)?;
    }
    Ok(())
}

/// Removes whatever `apply_auth` installed for `peer` on `fd`.
pub fn remove_auth(fd: RawFd, peer: IpAddr, auth: &ResolvedAuth) -> io::Result<()> {
    match auth {
        ResolvedAuth::Md5(_) => nos_tcp_auth::remove_md5_key(fd, peer),
        ResolvedAuth::Ao(keys) => {
            for key in keys {
                nos_tcp_auth::delete_ao_key(fd, peer, key.send_id, key.recv_id)?;
            }
            Ok(())
        }
    }
}

/// Binds a listening socket at `local`, scoped into `vrf` (see `connect`)
/// when required. `SO_REUSEADDR` is set so a restart doesn't have to wait
/// out `TIME_WAIT` on a previously accepted connection's port. An IPv6
/// socket is forced `IPV6_V6ONLY` — Linux's default dual-stack behavior
/// would otherwise make `[::]:179` also claim the v4 port, colliding with
/// the separate `0.0.0.0:179` socket `SessionManager` binds alongside it.
pub fn bind_listener(local: SocketAddr, vrf: Option<&str>) -> io::Result<TcpListener> {
    let socket = new_socket(local.is_ipv4())?;
    socket.set_reuseaddr(true)?;
    if local.is_ipv6() {
        SockRef::from(&socket).set_only_v6(true)?;
    }
    // RFC 5082: the SYN-ACK and everything an accepted socket sends inherit
    // the listener's TTL, and a GTSM peer drops anything below 255 — so it
    // must be 255 here, before accept (`apply_max_hops` then adds the
    // per-peer minimum). ponytail: also 255 for peers without max-hops, which
    // is harmless; the per-peer minimum is what enforces GTSM.
    if local.is_ipv6() {
        SockRef::from(&socket).set_unicast_hops_v6(255)?;
    } else {
        SockRef::from(&socket).set_ttl_v4(255)?;
    }
    if let Some(vrf) = vrf {
        bind_device(&socket, vrf)?;
    }
    socket.bind(local)?;
    socket.listen(1024)
}

fn new_socket(v4: bool) -> io::Result<TcpSocket> {
    if v4 {
        TcpSocket::new_v4()
    } else {
        TcpSocket::new_v6()
    }
}

fn bind_device(socket: &TcpSocket, vrf: &str) -> io::Result<()> {
    SockRef::from(socket).bind_device(Some(vrf.as_bytes()))
}
