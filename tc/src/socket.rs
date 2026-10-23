//! The only I/O: one `NETLINK_ROUTE` socket per call. Blocking, so run it on
//! `spawn_blocking`.

use std::io;

use netlink_sys::{protocols::NETLINK_ROUTE, Socket, SocketAddr};

use crate::decode::{self, FilterStats};
use crate::encode::{self, Hook, Request};

fn open() -> io::Result<Socket> {
    let mut socket = Socket::new(NETLINK_ROUTE)?;
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
