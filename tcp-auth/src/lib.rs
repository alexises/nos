//! Raw Linux `setsockopt` bindings for TCP session authentication:
//! `TCP_MD5SIG` (RFC 2385) and TCP-AO (RFC 5925, kernel >= 5.20).
//!
//! Neither option has a maintained wrapper in `socket2`/`nix` or a dedicated
//! crate on crates.io, so the kernel struct layouts are hand-written here
//! from `include/uapi/linux/tcp.h`. This is the one crate in the workspace
//! whose whole purpose is raw FFI — every `unsafe` block here is confined to
//! `setsockopt` calls and `sockaddr_storage` construction, each documented
//! at its use site.
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

/// RFC 5925's two mandatory-to-implement algorithms, named for the Linux
/// crypto API (`alg_name` in `struct tcp_ao_add`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AoAlgorithm {
    HmacSha1_96,
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
/// outgoing segments.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AoKey {
    pub send_id: u8,
    pub recv_id: u8,
    pub algorithm: AoAlgorithm,
    pub key: Vec<u8>,
    pub set_current: bool,
    pub set_rnext: bool,
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

/// Adds one TCP-AO key (`TCP_AO_ADD_KEY`) for `peer` to this socket. Adding a
/// key with the same `(send_id, recv_id, peer)` as an existing one replaces
/// it. `key.key` must be at most [`MAX_KEY_LEN`] bytes.
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
    add.ifindex = -1; // VRF scoping already applied via SO_BINDTODEVICE on this socket.
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
    add.keyflags = 0;
    add.keylen = u8::try_from(key.key.len()).expect("checked above");
    add.key[..key.key.len()].copy_from_slice(&key.key);
    setsockopt(fd, TCP_AO_ADD_KEY, &add)
}

/// Removes one TCP-AO key (`TCP_AO_DEL_KEY`) identified by `(send_id,
/// recv_id)` for `peer` from this socket.
pub fn delete_ao_key(fd: RawFd, peer: IpAddr, send_id: u8, recv_id: u8) -> io::Result<()> {
    let mut del: TcpAoDel = zeroed();
    write_sockaddr(&mut del.addr, peer);
    del.ifindex = -1;
    del.prefix = prefix_len(peer);
    del.sndid = send_id;
    del.rcvid = recv_id;
    setsockopt(fd, TCP_AO_DEL_KEY, &del)
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
}
