//! Raw Linux `setsockopt` bindings for TCP session authentication:
//! `TCP_MD5SIG` (RFC 2385) and TCP-AO (RFC 5925, kernel >= 5.20).
//!
//! Neither option has a maintained wrapper in `socket2`/`nix` or a dedicated
//! crate on crates.io, so the kernel struct layouts are hand-written here
//! from `include/uapi/linux/tcp.h`. This is the one crate in the workspace
//! whose whole purpose is raw FFI — every `unsafe` block here is confined to
//! `setsockopt` calls and `sockaddr_storage` construction, each documented
//! at its use site.
#![warn(missing_docs)]
#![allow(unsafe_code)]

use std::io;
use std::mem;
use std::net::{IpAddr, Ipv4Addr};
use std::os::fd::RawFd;

/// `TCP_MD5SIG_MAXKEYLEN` / `TCP_AO_MAXKEYLEN` — both 80 in `linux/tcp.h`.
pub const MAX_KEY_LEN: usize = 80;

const TCP_MD5SIG: libc::c_int = 14;
const TCP_AO_ADD_KEY: libc::c_int = 38;
const TCP_AO_DEL_KEY: libc::c_int = 39;
const TCP_AO_INFO: libc::c_int = 40;

/// `tcp_ao_info_opt` flag bits: `set_rnext` (bit 1), and the two state bits
/// a getsockopt reports that a setsockopt would overwrite — `ao_required`
/// (bit 2) and `accept_icmps` (bit 4) — which `set_ao_rnext` re-sends as read.
const AO_INFO_SET_RNEXT: u32 = 1 << 1;
const AO_INFO_KEEP: u32 = (1 << 2) | (1 << 4);

/// `TCP_AO_KEYF_EXCLUDE_OPT` (`include/uapi/linux/tcp.h`) — the
/// `tcp_ao_add`/`tcp_ao_del`/`tcp_ao_info_opt` `keyflags`/`flags` bit
/// (RFC 5925 §5.2) excluding TCP options from this key's MAC coverage. Bit 0
/// of the same byte is `TCP_AO_KEYF_IFINDEX`, unused by this crate.
const TCP_AO_KEYF_EXCLUDE_OPT: u8 = 1 << 1;

/// RFC 5925's two mandatory-to-implement algorithms, named for the Linux
/// crypto API (`alg_name` in `struct tcp_ao_add`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AoAlgorithm {
    /// HMAC-SHA-1 truncated to 96 bits (RFC 5926 §2.2), kernel name `hmac(sha1)`.
    HmacSha1_96,
    /// AES-128-CMAC truncated to 96 bits (RFC 5926 §2.2), kernel name `cmac(aes)`.
    AesCmac96,
}

impl AoAlgorithm {
    fn kernel_name(self) -> &'static str {
        match self {
            AoAlgorithm::HmacSha1_96 => "hmac(sha1)",
            AoAlgorithm::AesCmac96 => "cmac(aes)",
        }
    }
}

/// One TCP-AO key to install via [`add_ao_key`]. `set_current`/`set_rnext`
/// mirror `struct tcp_ao_add`'s same-named bits — the kernel requires
/// exactly one key with `set_current` for a socket to actually sign
/// outgoing segments. `exclude_options` is RFC 5925 §5.2's MAC-coverage
/// choice (`TCP_AO_KEYF_EXCLUDE_OPT`) — both peers must agree on it or
/// authentication fails.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AoKey {
    /// `KeyID` we put on segments we send (RFC 5925 §3.1; `sndid` in `tcp_ao_add`).
    pub send_id: u8,
    /// `RecvID` the peer puts on segments we verify with this key (`rcvid` in `tcp_ao_add`).
    pub recv_id: u8,
    /// MAC algorithm of this key.
    pub algorithm: AoAlgorithm,
    /// The master key bytes (RFC 5925 §3.1).
    pub key: Vec<u8>,
    /// Make this the key that signs outgoing segments (`set_current` in `tcp_ao_add`).
    pub set_current: bool,
    /// Ask the peer to sign with this key (`set_rnext`, the `RNextKeyID` we send).
    pub set_rnext: bool,
    /// Exclude TCP options from the MAC (RFC 5925 §5.2, `TCP_AO_KEYF_EXCLUDE_OPT`).
    pub exclude_options: bool,
}

/// Sets (or replaces) this socket's `TCP_MD5SIG` key for `peer`. `key` must
/// be non-empty and at most [`MAX_KEY_LEN`] bytes.
pub fn set_md5_key(fd: RawFd, peer: IpAddr, key: &[u8]) -> io::Result<()> {
    set_md5_key_raw(fd, peer, key)
}

/// Removes this socket's `TCP_MD5SIG` key for `peer` (a zero-length key is
/// the kernel's documented delete signal).
pub fn remove_md5_key(fd: RawFd, peer: IpAddr) -> io::Result<()> {
    set_md5_key_raw(fd, peer, &[])
}

/// Adds one TCP-AO key (`TCP_AO_ADD_KEY`) for `peer` to this socket. The
/// kernel refuses (`EEXIST`) a key whose `SendID` *or* `RecvID` overlaps an
/// existing key for that peer (RFC 5925 §3.1) — it never replaces one.
/// `key.key` must be at most [`MAX_KEY_LEN`] bytes.
pub fn add_ao_key(fd: RawFd, peer: IpAddr, key: &AoKey) -> io::Result<()> {
    if key.key.len() > MAX_KEY_LEN {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "TCP-AO key exceeds TCP_AO_MAXKEYLEN (80 bytes)",
        ));
    }
    let mut add: TcpAoAdd = zeroed();
    write_sockaddr(&mut add.addr, peer);
    let alg_name = key.algorithm.kernel_name().as_bytes();
    add.alg_name[..alg_name.len()].copy_from_slice(alg_name);
    // 0, not -1: `ifindex` is only meaningful with `TCP_AO_KEYF_IFINDEX` set
    // (never done here) — the kernel rejects any other value with EINVAL.
    // VRF scoping is already applied via SO_BINDTODEVICE on this socket.
    add.ifindex = 0;
    let mut flags: u32 = 0;
    if key.set_current {
        flags |= 1 << 0;
    }
    if key.set_rnext {
        flags |= 1 << 1;
    }
    add.flags = flags;
    add.prefix = prefix_len(peer);
    add.sndid = key.send_id;
    add.rcvid = key.recv_id;
    add.maclen = 0; // 0 => kernel default truncated MAC length for the algorithm.
    add.keyflags = if key.exclude_options {
        TCP_AO_KEYF_EXCLUDE_OPT
    } else {
        0
    };
    add.keylen = u8::try_from(key.key.len()).expect("checked above");
    add.key[..key.key.len()].copy_from_slice(&key.key);
    setsockopt(fd, TCP_AO_ADD_KEY, &add)
}

/// Removes one TCP-AO key (`TCP_AO_DEL_KEY`) identified by `(send_id,
/// recv_id)` for `peer` from this socket.
pub fn delete_ao_key(fd: RawFd, peer: IpAddr, send_id: u8, recv_id: u8) -> io::Result<()> {
    let mut del: TcpAoDel = zeroed();
    write_sockaddr(&mut del.addr, peer);
    del.ifindex = 0; // see add_ao_key's comment on ifindex.
    del.prefix = prefix_len(peer);
    del.sndid = send_id;
    del.rcvid = recv_id;
    setsockopt(fd, TCP_AO_DEL_KEY, &del)
}

/// One connection's live TCP-AO state, from `getsockopt(TCP_AO_INFO)`
/// (RFC 5925 §7.2/§7.5): the `KeyID` currently signing outgoing segments, the
/// `RecvID` of our own rnext key (the `RNextKeyID` *we* ask the peer to send
/// with — the peer's request shows up as `current_key` moving), and per-connection
/// verification counters since the kernel installed AO on this socket
/// (reset on every reconnect, not cumulative across a peer's whole
/// lifetime).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AoInfo {
    /// `KeyID` currently signing outgoing segments.
    pub current_key: u8,
    /// `RecvID` of our rnext key, the `RNextKeyID` we ask the peer to send with.
    pub rnext_key: u8,
    /// Segments that passed AO verification since AO was installed.
    pub pkt_good: u64,
    /// Segments that failed AO verification (bad MAC).
    pub pkt_bad: u64,
    /// Segments whose KeyID/RecvID matched no installed key.
    pub pkt_key_not_found: u64,
}

/// Reads `fd`'s current TCP-AO state (`getsockopt(TCP_AO_INFO)`). Errors if
/// `fd` never had a TCP-AO key installed, or is no longer a valid/open fd
/// (e.g. a session that ended between a caller reading `fd` and calling
/// this).
pub fn get_ao_info(fd: RawFd) -> io::Result<AoInfo> {
    let info = read_ao_info(fd)?;
    Ok(AoInfo {
        current_key: info.current_key,
        rnext_key: info.rnext,
        pkt_good: info.pkt_good,
        pkt_bad: info.pkt_bad,
        pkt_key_not_found: info.pkt_key_not_found,
    })
}

/// Sets this connection's rnext key (`TCP_AO_INFO` with `set_rnext`) to the
/// key whose `RecvID` is `rnext_recv_id`: the `RNextKeyID` we advertise, asking
/// the peer to start signing with it (RFC 5925 §7.5). The kernel writes
/// `ao_required`/`accept_icmps` from the same command, so the current values
/// are read back and re-sent unchanged.
pub fn set_ao_rnext(fd: RawFd, rnext_recv_id: u8) -> io::Result<()> {
    let mut info = read_ao_info(fd)?;
    info.flags &= AO_INFO_KEEP;
    info.flags |= AO_INFO_SET_RNEXT;
    info.rnext = rnext_recv_id;
    info.pkt_good = 0;
    info.pkt_bad = 0;
    info.pkt_key_not_found = 0;
    info.pkt_ao_required = 0;
    info.pkt_dropped_icmp = 0;
    setsockopt(fd, TCP_AO_INFO, &info)
}

fn read_ao_info(fd: RawFd) -> io::Result<TcpAoInfoOpt> {
    let mut info: TcpAoInfoOpt = zeroed();
    let mut len = libc::socklen_t::try_from(mem::size_of::<TcpAoInfoOpt>())
        .expect("fixed, small struct size");
    // SAFETY: `fd` is caller-supplied, `info` is a valid `&mut` for `len`
    // bytes matching the kernel's `TCP_AO_INFO` optval shape.
    let ret = unsafe {
        libc::getsockopt(
            fd,
            libc::IPPROTO_TCP,
            TCP_AO_INFO,
            std::ptr::from_mut(&mut info).cast::<libc::c_void>(),
            &raw mut len,
        )
    };
    if ret != 0 {
        return Err(io::Error::last_os_error());
    }
    if len as usize != mem::size_of::<TcpAoInfoOpt>() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "kernel returned unexpected size for TCP_AO_INFO",
        ));
    }
    Ok(info)
}

fn set_md5_key_raw(fd: RawFd, peer: IpAddr, key: &[u8]) -> io::Result<()> {
    if key.len() > MAX_KEY_LEN {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "MD5 key exceeds TCP_MD5SIG_MAXKEYLEN (80 bytes)",
        ));
    }
    let mut sig: TcpMd5Sig = zeroed();
    write_sockaddr(&mut sig.addr, peer);
    sig.keylen = u16::try_from(key.len()).expect("checked above");
    sig.key[..key.len()].copy_from_slice(key);
    setsockopt(fd, TCP_MD5SIG, &sig)
}

/// Enables RFC 5082 GTSM on `fd` for a peer at most `hops` routers away
/// (1 = directly connected): sends with TTL/hop-limit 255 and has the
/// kernel drop received packets below `256 - hops` (`IP_MINTTL` /
/// `IPV6_MINHOPCOUNT`). `hops` must be 1..=255. Unlike the key options this
/// is per-socket, not per-peer, so on a listener it would affect every peer;
/// apply it to a connect socket before `connect()` or an accepted stream.
pub fn set_max_hops(fd: RawFd, v6: bool, hops: u8) -> io::Result<()> {
    if hops == 0 {
        return Err(io::Error::from(io::ErrorKind::InvalidInput));
    }
    let min = libc::c_int::from(255 - (hops - 1));
    let (level, ttl, minttl) = if v6 {
        (
            libc::IPPROTO_IPV6,
            libc::IPV6_UNICAST_HOPS,
            libc::IPV6_MINHOPCOUNT,
        )
    } else {
        (libc::IPPROTO_IP, libc::IP_TTL, libc::IP_MINTTL)
    };
    setsockopt_int(fd, level, ttl, 255)?;
    setsockopt_int(fd, level, minttl, min)
}

/// Sets `IPV6_CHECKSUM` at `IPPROTO_IPV6` level to `offset` — the byte
/// offset within the payload of a field the kernel should fill with the
/// ICMPv6-style pseudo-header checksum on send and verify on receive.
/// Passing a negative `offset` disables kernel checksumming (used when a
/// caller computes its own, e.g. inside an authenticated payload). Not
/// exposed by `socket2`, so it goes through the same raw-`setsockopt`
/// helper as [`set_max_hops`].
pub fn set_ipv6_checksum(fd: RawFd, offset: libc::c_int) -> io::Result<()> {
    setsockopt_int(fd, libc::IPPROTO_IPV6, libc::IPV6_CHECKSUM, offset)
}

fn setsockopt_int(
    fd: RawFd,
    level: libc::c_int,
    name: libc::c_int,
    value: libc::c_int,
) -> io::Result<()> {
    // SAFETY: `fd` is a caller-supplied open socket and `&value` is a valid
    // `c_int` for the `size_of::<c_int>()` bytes passed.
    let ret = unsafe {
        libc::setsockopt(
            fd,
            level,
            name,
            std::ptr::from_ref(&value).cast::<libc::c_void>(),
            libc::socklen_t::try_from(mem::size_of::<libc::c_int>()).expect("4 bytes"),
        )
    };
    if ret == 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}

fn prefix_len(addr: IpAddr) -> u8 {
    match addr {
        IpAddr::V4(_) => 32,
        IpAddr::V6(_) => 128,
    }
}

/// Zero-initializes a `#[repr(C)]` FFI struct — every field of every struct
/// below is a plain integer/byte-array type, so the all-zero bit pattern is
/// always a valid value.
fn zeroed<T>() -> T {
    // SAFETY: `T` is always one of this crate's own `#[repr(C)]` structs
    // (`TcpMd5Sig`/`TcpAoAdd`/`TcpAoDel`/`libc::sockaddr_storage`), whose
    // fields are all integers or byte arrays with no invalid bit pattern.
    unsafe { mem::zeroed() }
}

/// Writes `addr`'s family/port/address into a `sockaddr_storage` that was
/// previously zeroed — `sin_zero`/`sin6_flowinfo`/`sin6_scope_id` are left
/// at zero, which is correct: only family + address matter for key lookup.
fn write_sockaddr(storage: &mut libc::sockaddr_storage, addr: IpAddr) {
    match addr {
        IpAddr::V4(v4) => {
            let family = sa_family(libc::AF_INET);
            // SAFETY: `storage` is `sockaddr_storage`-sized/aligned (>=
            // `sockaddr_in`'s requirements), and was zeroed, so writing a
            // `sockaddr_in` into its start leaves a valid, fully-initialized
            // `sockaddr_in` there with every other byte still zero.
            let sin = std::ptr::from_mut(storage).cast::<libc::sockaddr_in>();
            unsafe {
                (*sin).sin_family = family;
                (*sin).sin_addr = libc::in_addr {
                    s_addr: ipv4_to_s_addr(v4),
                };
            }
        }
        IpAddr::V6(v6) => {
            let family = sa_family(libc::AF_INET6);
            // SAFETY: same reasoning as the v4 arm, for `sockaddr_in6`.
            let sin6 = std::ptr::from_mut(storage).cast::<libc::sockaddr_in6>();
            unsafe {
                (*sin6).sin6_family = family;
                (*sin6).sin6_addr = libc::in6_addr {
                    s6_addr: v6.octets(),
                };
            }
        }
    }
}

fn sa_family(af: libc::c_int) -> libc::sa_family_t {
    libc::sa_family_t::try_from(af).expect("AF_INET/AF_INET6 always fit sa_family_t")
}

/// `in_addr.s_addr`'s in-memory bytes must equal `Ipv4Addr::octets()`
/// exactly (both are "network byte order"); `from_ne_bytes` followed by the
/// field's own native storage is the identity on every platform, so this is
/// portable despite looking like a byte-order operation.
fn ipv4_to_s_addr(addr: Ipv4Addr) -> u32 {
    u32::from_ne_bytes(addr.octets())
}

fn setsockopt<T>(fd: RawFd, name: libc::c_int, value: &T) -> io::Result<()> {
    // SAFETY: `fd` is a caller-supplied open socket, `value` is a valid
    // `&T` for `size_of::<T>()` bytes, and `T` is always one of this
    // crate's own fixed-layout structs matching the kernel's expected
    // `optval` shape for `name`.
    let ret = unsafe {
        libc::setsockopt(
            fd,
            libc::IPPROTO_TCP,
            name,
            std::ptr::from_ref(value).cast::<libc::c_void>(),
            libc::socklen_t::try_from(mem::size_of::<T>()).expect("fixed, small struct size"),
        )
    };
    if ret == 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}

/// `struct tcp_md5sig` (`include/uapi/linux/tcp.h`) — for `setsockopt(TCP_MD5SIG)`.
#[repr(C)]
struct TcpMd5Sig {
    addr: libc::sockaddr_storage, // tcpm_addr
    flags: u8,                    // tcpm_flags — always 0 here (no TCP_MD5SIG_EXT use)
    prefixlen: u8,                // tcpm_prefixlen — unused unless FLAG_PREFIX is set
    keylen: u16,                  // tcpm_keylen
    ifindex: i32,                 // tcpm_ifindex — unused unless FLAG_IFINDEX is set
    key: [u8; MAX_KEY_LEN],       // tcpm_key
}

/// `struct tcp_ao_add` (`include/uapi/linux/tcp.h`) — for
/// `setsockopt(TCP_AO_ADD_KEY)`. The kernel's `set_current:1, set_rnext:1,
/// reserved:30` C bitfield is represented as a plain `u32` (Rust has no
/// bitfield support); on every architecture this workspace targets,
/// bitfields are allocated LSB-first, so bit 0 is `set_current` and bit 1 is
/// `set_rnext`.
#[repr(C, align(8))]
struct TcpAoAdd {
    addr: libc::sockaddr_storage,
    alg_name: [u8; 64],
    ifindex: i32,
    flags: u32,
    reserved2: u16,
    prefix: u8,
    sndid: u8,
    rcvid: u8,
    maclen: u8,
    keyflags: u8,
    keylen: u8,
    key: [u8; MAX_KEY_LEN],
}

/// `struct tcp_ao_del` (`include/uapi/linux/tcp.h`) — for
/// `setsockopt(TCP_AO_DEL_KEY)`. Same bitfield representation as
/// [`TcpAoAdd`] (`set_current:1, set_rnext:1, del_async:1, reserved:29`);
/// this crate never sets `del_async` (listening-socket-only, unused here).
#[repr(C, align(8))]
struct TcpAoDel {
    addr: libc::sockaddr_storage,
    ifindex: i32,
    flags: u32,
    reserved2: u16,
    prefix: u8,
    sndid: u8,
    rcvid: u8,
    current_key: u8,
    rnext: u8,
    keyflags: u8,
}

/// `struct tcp_ao_info_opt` (`include/uapi/linux/tcp.h`) — for
/// `getsockopt`/`setsockopt(TCP_AO_INFO)`. The kernel's `set_current:1,
/// set_rnext:1, ao_required:1, set_counters:1, accept_icmps:1, reserved:27`
/// bitfield is "in" (which fields to apply) for setsockopt and "out"
/// (`ao_required`/`accept_icmps` state) for getsockopt; same LSB-first
/// layout as [`TcpAoAdd`]. Only `set_ao_rnext` writes it.
#[repr(C, align(8))]
struct TcpAoInfoOpt {
    flags: u32,
    reserved2: u16,
    current_key: u8,
    rnext: u8,
    pkt_good: u64,
    pkt_bad: u64,
    pkt_key_not_found: u64,
    pkt_ao_required: u64,
    pkt_dropped_icmp: u64,
}

#[cfg(test)]
mod tests {
    use std::net::Ipv6Addr;

    use super::*;

    // Struct sizes/alignment must exactly match the kernel UAPI layout —
    // these don't need root or a real kernel, just a stable ABI.
    #[test]
    fn tcp_md5sig_matches_kernel_layout() {
        assert_eq!(mem::size_of::<TcpMd5Sig>(), 128 + 1 + 1 + 2 + 4 + 80);
    }

    #[test]
    fn tcp_ao_add_matches_kernel_layout() {
        assert_eq!(mem::size_of::<TcpAoAdd>(), 128 + 64 + 4 + 4 + 2 + 6 + 80);
        assert_eq!(mem::align_of::<TcpAoAdd>(), 8);
    }

    #[test]
    fn tcp_ao_del_matches_kernel_layout() {
        assert_eq!(mem::size_of::<TcpAoDel>(), 128 + 4 + 4 + 2 + 6);
        assert_eq!(mem::align_of::<TcpAoDel>(), 8);
    }

    #[test]
    fn tcp_ao_info_opt_matches_kernel_layout() {
        assert_eq!(mem::size_of::<TcpAoInfoOpt>(), 4 + 2 + 1 + 1 + 8 * 5);
        assert_eq!(mem::align_of::<TcpAoInfoOpt>(), 8);
    }

    #[test]
    fn ipv4_s_addr_round_trips_octets() {
        let addr = Ipv4Addr::new(10, 0, 0, 1);
        assert_eq!(ipv4_to_s_addr(addr).to_ne_bytes(), addr.octets());
    }

    #[test]
    fn write_sockaddr_v4_sets_family_and_address() {
        let mut storage: libc::sockaddr_storage = zeroed();
        write_sockaddr(&mut storage, IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)));
        let sin = std::ptr::from_ref(&storage).cast::<libc::sockaddr_in>();
        // SAFETY: just written above as a valid sockaddr_in.
        let sin = unsafe { *sin };
        assert_eq!(sin.sin_family, sa_family(libc::AF_INET));
        assert_eq!(sin.sin_addr.s_addr.to_ne_bytes(), [192, 0, 2, 1]);
    }

    #[test]
    fn write_sockaddr_v6_sets_family_and_address() {
        let v6 = Ipv6Addr::new(0x2001, 0x0db8, 0, 0, 0, 0, 0, 1);
        let mut storage: libc::sockaddr_storage = zeroed();
        write_sockaddr(&mut storage, IpAddr::V6(v6));
        let sin6 = std::ptr::from_ref(&storage).cast::<libc::sockaddr_in6>();
        // SAFETY: just written above as a valid sockaddr_in6.
        let sin6 = unsafe { *sin6 };
        assert_eq!(sin6.sin6_family, sa_family(libc::AF_INET6));
        assert_eq!(sin6.sin6_addr.s6_addr, v6.octets());
    }

    #[test]
    fn oversized_md5_key_is_rejected() {
        let err = set_md5_key(-1, IpAddr::V4(Ipv4Addr::LOCALHOST), &[0u8; 81]).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidInput);
    }

    #[test]
    fn oversized_ao_key_is_rejected() {
        let key = AoKey {
            send_id: 1,
            recv_id: 1,
            algorithm: AoAlgorithm::HmacSha1_96,
            key: vec![0u8; 81],
            set_current: true,
            set_rnext: false,
            exclude_options: false,
        };
        let err = add_ao_key(-1, IpAddr::V4(Ipv4Addr::LOCALHOST), &key).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidInput);
    }
}

#[cfg(test)]
mod max_hops_tests {
    use super::*;
    use std::os::fd::AsRawFd;

    fn get(fd: RawFd, level: libc::c_int, name: libc::c_int) -> libc::c_int {
        let mut v: libc::c_int = 0;
        let mut len = libc::socklen_t::try_from(mem::size_of::<libc::c_int>()).unwrap();
        // SAFETY: valid fd and a c_int-sized out buffer.
        let r = unsafe {
            libc::getsockopt(
                fd,
                level,
                name,
                std::ptr::from_mut(&mut v).cast(),
                &raw mut len,
            )
        };
        assert_eq!(r, 0);
        v
    }

    #[test]
    fn sets_ttl_255_and_min_ttl() {
        let s = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        set_max_hops(s.as_raw_fd(), false, 1).unwrap();
        assert_eq!(get(s.as_raw_fd(), libc::IPPROTO_IP, libc::IP_TTL), 255);
        assert_eq!(get(s.as_raw_fd(), libc::IPPROTO_IP, libc::IP_MINTTL), 255);
        set_max_hops(s.as_raw_fd(), false, 3).unwrap();
        assert_eq!(get(s.as_raw_fd(), libc::IPPROTO_IP, libc::IP_MINTTL), 253);
        assert!(set_max_hops(s.as_raw_fd(), false, 0).is_err());
    }

    #[test]
    fn sets_v6_hop_limit_and_min_hop_count() {
        let Ok(s) = std::net::TcpListener::bind("[::1]:0") else {
            return; // no IPv6 on this host
        };
        set_max_hops(s.as_raw_fd(), true, 2).unwrap();
        let fd = s.as_raw_fd();
        assert_eq!(get(fd, libc::IPPROTO_IPV6, libc::IPV6_UNICAST_HOPS), 255);
        assert_eq!(get(fd, libc::IPPROTO_IPV6, libc::IPV6_MINHOPCOUNT), 254);
    }

    #[test]
    fn ipv6_checksum_on_a_bad_fd_errors() {
        assert!(set_ipv6_checksum(-1, 2).is_err());
    }
}

/// Real `setsockopt`s on an unprivileged localhost socket (#131).
#[cfg(test)]
mod kernel_tests {
    use super::*;
    use std::net::Ipv6Addr;
    use std::os::fd::AsRawFd;

    const PEER: IpAddr = IpAddr::V4(Ipv4Addr::LOCALHOST);

    #[test]
    fn md5_key_set_replace_and_remove() {
        let s = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let fd = s.as_raw_fd();
        set_md5_key(fd, PEER, b"secret").unwrap();
        set_md5_key(fd, PEER, b"other").unwrap();
        set_md5_key(fd, IpAddr::V6(Ipv6Addr::LOCALHOST), b"v6").unwrap_or(());
        remove_md5_key(fd, PEER).unwrap();
        assert!(set_md5_key(-1, PEER, b"x").is_err());
    }

    fn key(send_id: u8, algorithm: AoAlgorithm, exclude_options: bool) -> AoKey {
        AoKey {
            send_id,
            recv_id: send_id,
            algorithm,
            key: b"ao-secret".to_vec(),
            // A listening socket refuses current/rnext (EINVAL).
            set_current: false,
            set_rnext: false,
            exclude_options,
        }
    }

    #[test]
    fn ao_key_add_info_and_delete() {
        let s = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let fd = s.as_raw_fd();
        match add_ao_key(fd, PEER, &key(1, AoAlgorithm::HmacSha1_96, false)) {
            Ok(()) => {}
            // Kernel without TCP-AO (or its crypto): the error path is all
            // there is to cover here.
            Err(e) => {
                assert!(matches!(
                    e.raw_os_error(),
                    Some(libc::ENOPROTOOPT | libc::ENOENT | libc::EOPNOTSUPP)
                ));
                return;
            }
        }
        add_ao_key(fd, PEER, &key(2, AoAlgorithm::AesCmac96, true)).unwrap_or(());
        // A listener has AO info but no established connection to report on;
        // either answer exercises the getsockopt path.
        let _ = get_ao_info(fd);
        delete_ao_key(fd, PEER, 1, 1).unwrap_or(());
        assert!(get_ao_info(-1).is_err());
    }

    /// RFC 5925 §7.5.2 on a real loopback pair: one side asks for key 2 as
    /// rnext, the other's `current_key` follows without any `set_current`.
    #[test]
    fn peer_rnext_advances_current_key() {
        use std::io::{Read, Write};
        let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = l.local_addr().unwrap();
        let lfd = l.as_raw_fd();
        if let Err(e) = add_ao_key(lfd, PEER, &key(1, AoAlgorithm::HmacSha1_96, false)) {
            assert!(matches!(
                e.raw_os_error(),
                Some(libc::ENOPROTOOPT | libc::ENOENT | libc::EOPNOTSUPP)
            ));
            return;
        }
        add_ao_key(lfd, PEER, &key(2, AoAlgorithm::HmacSha1_96, false)).unwrap();
        let sock =
            socket2::Socket::new(socket2::Domain::IPV4, socket2::Type::STREAM, None).unwrap();
        let cfd = sock.as_raw_fd();
        let mut k1 = key(1, AoAlgorithm::HmacSha1_96, false);
        k1.set_current = true;
        k1.set_rnext = true;
        add_ao_key(cfd, PEER, &k1).unwrap();
        add_ao_key(cfd, PEER, &key(2, AoAlgorithm::HmacSha1_96, false)).unwrap();
        sock.connect(&addr.into()).unwrap();
        let (mut srv, _) = l.accept().unwrap();
        let sfd = srv.as_raw_fd();
        let mut cli = std::net::TcpStream::from(sock);
        let exchange = |a: &mut std::net::TcpStream, b: &mut std::net::TcpStream| {
            a.write_all(b"x").unwrap();
            let mut buf = [0u8; 1];
            b.read_exact(&mut buf).unwrap();
        };
        exchange(&mut cli, &mut srv);
        exchange(&mut srv, &mut cli);
        assert_eq!(get_ao_info(sfd).unwrap().current_key, 1);
        // The client asks for key 2; the server follows on the next segment.
        set_ao_rnext(cfd, 2).unwrap();
        assert_eq!(get_ao_info(cfd).unwrap().rnext_key, 2);
        exchange(&mut cli, &mut srv);
        exchange(&mut srv, &mut cli);
        assert_eq!(get_ao_info(sfd).unwrap().current_key, 2);
        // The client's own current key is untouched until the server asks.
        assert_eq!(get_ao_info(cfd).unwrap().current_key, 1);
        // The server's own rnext is still key 1 (an accepted socket copies the
        // SYN's KeyID): key 1 is busy until it is moved, as is the current key.
        assert_eq!(
            delete_ao_key(sfd, PEER, 1, 1).unwrap_err().raw_os_error(),
            Some(libc::EBUSY)
        );
        set_ao_rnext(sfd, 2).unwrap();
        delete_ao_key(sfd, PEER, 1, 1).unwrap();
        assert_eq!(
            delete_ao_key(sfd, PEER, 2, 2).unwrap_err().raw_os_error(),
            Some(libc::EBUSY)
        );
    }
}
