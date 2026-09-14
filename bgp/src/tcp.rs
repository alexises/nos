use std::io;
use std::net::{IpAddr, SocketAddr};

use socket2::SockRef;
use tokio::net::{TcpListener, TcpSocket, TcpStream};
use tracing::warn;

/// Opens an outbound TCP connection to `remote`, optionally bound to
/// `source` (the peer-group's configured transport source address) and, on
/// Linux, scoped into `vrf` via `SO_BINDTODEVICE` — the same mechanism
/// `nos-ribd`'s driver uses at the kernel level, applied here at the socket
/// level since `nos-bgpd` never touches `rtnetlink` directly.
pub async fn connect(
    remote: SocketAddr,
    source: Option<IpAddr>,
    vrf: Option<&str>,
) -> io::Result<TcpStream> {
    let socket = new_socket(remote.is_ipv4())?;
    if let Some(vrf) = vrf {
        bind_device(&socket, vrf)?;
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
