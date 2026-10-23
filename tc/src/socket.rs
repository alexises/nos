//! The only I/O: one `NETLINK_ROUTE` socket per call. Blocking, so run it on
//! `spawn_blocking`.

use std::io;

use netlink_sys::{
    protocols::{NETLINK_GENERIC, NETLINK_ROUTE},
    Socket, SocketAddr,
};

use crate::decode::{self, FilterStats};
use crate::encode::{self, Hook, Request};
use crate::genl::{self, Psample, Sample};

fn open() -> io::Result<Socket> {
    open_proto(NETLINK_ROUTE)
}

fn open_proto(protocol: isize) -> io::Result<Socket> {
    let mut socket = Socket::new(protocol)?;
    socket.bind_auto()?;
    socket.connect(&SocketAddr::new(0, 0))?;
    Ok(socket)
}

/// Sends one request and waits for its acknowledgement. `tolerate` are
/// errnos (positive) that count as success.
pub fn send(req: &Request, tolerate: &[i32]) -> io::Result<()> {
    let msg = encode::encode(req, 1)?;
    let socket = open()?;
    socket.send(&msg, 0)?;
    let mut reply = Vec::with_capacity(4096);
    socket.recv(&mut reply, 0)?;
    decode::ack(&reply, tolerate)
}

/// Every action's counters of every filter in `chain` at `hook`. A chain
/// that does not exist is an empty list.
pub fn dump(ifindex: u32, hook: Hook, chain: u32) -> io::Result<Vec<FilterStats>> {
    let socket = open()?;
    socket.send(&encode::dump_request(ifindex, hook, chain, 1), 0)?;
    let mut out = Vec::new();
    let mut buf = Vec::with_capacity(1 << 16);
    loop {
        buf.clear();
        socket.recv(&mut buf, 0)?;
        if decode::dump_part(&buf, &mut out)? {
            return Ok(out);
        }
    }
}

/// Resolves the `psample` family. `ENOENT` while the module is not loaded
/// (installing an `act_sample` action loads it).
pub fn psample() -> io::Result<Psample> {
    let socket = open_proto(NETLINK_GENERIC)?;
    socket.send(&genl::family_request("psample", 1), 0)?;
    let mut reply = Vec::with_capacity(4096);
    socket.recv(&mut reply, 0)?;
    genl::psample_reply(&reply)
}

/// A member of psample's `packets` group (needs `CAP_NET_ADMIN`). Blocking.
pub struct SampleSocket {
    socket: Socket,
    family: u16,
    buf: Vec<u8>,
}

impl SampleSocket {
    pub fn open(p: &Psample) -> io::Result<Self> {
        let socket = open_proto(NETLINK_GENERIC)?;
        socket.add_membership(p.group)?;
        Ok(Self {
            socket,
            family: p.family,
            buf: Vec::with_capacity(1 << 16),
        })
    }

    /// The samples of the next received buffer (possibly none). `ENOBUFS`
    /// means the kernel dropped some: the socket stays usable.
    pub fn recv(&mut self) -> io::Result<Vec<Sample>> {
        self.buf.clear();
        self.socket.recv(&mut self.buf, 0)?;
        genl::samples(&self.buf, self.family)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Unprivileged: the family resolves, or is absent while the module is
    /// not loaded; joining `packets` needs `CAP_NET_ADMIN` (the kernel test
    /// receives through it).
    #[test]
    fn psample_resolves_or_is_absent() {
        match psample() {
            Ok(p) => drop(SampleSocket::open(&p)),
            Err(e) => assert_eq!(e.raw_os_error(), Some(2), "{e}"),
        }
    }
}
