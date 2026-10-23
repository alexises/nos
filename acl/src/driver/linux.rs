//! `nos-tc` against the real kernel. Coverage-excluded like every
//! `driver/linux.rs`; the requests themselves are built and tested in
//! `driver/mod.rs`, and `tests/kernel.rs` plus the `acl` e2e phase run this.

use std::io;

use nos_tc::{dump, send, Request};

use super::{
    chain_requests, counters_from, entry_delete, entry_request, live_from, Counter, Direction,
    Driver, ACL_CHAIN_A, ACL_CHAIN_B,
};
use crate::compile::Compiled;

const EEXIST: i32 = 17;
const ENOENT: i32 = 2;
/// `RTM_DELCHAIN` on a chain only a `goto` still names.
const EINVAL: i32 = 22;

#[derive(Debug, Default)]
pub struct LinuxDriver;

impl Driver for LinuxDriver {
    fn live_chain(&mut self, ifindex: u32, dir: Direction) -> io::Result<Option<u32>> {
        Ok(live_from(&dump(ifindex, dir.hook(), 0)?))
    }

    fn install(
        &mut self,
        ifindex: u32,
        dir: Direction,
        chain: u32,
        acl: &Compiled,
    ) -> io::Result<()> {
        send(&Request::Clsact { ifindex }, &[EEXIST])?;
        self.flush(ifindex, dir, chain)?;
        for req in chain_requests(ifindex, dir, chain, acl) {
            send(&req, &[])?;
        }
        Ok(())
    }

    fn switch(&mut self, ifindex: u32, dir: Direction, chain: u32) -> io::Result<()> {
        send(&entry_request(ifindex, dir, chain), &[])
    }

    fn flush(&mut self, ifindex: u32, dir: Direction, chain: u32) -> io::Result<()> {
        let req = Request::FlushChain {
            ifindex,
            hook: dir.hook(),
            chain,
        };
        send(&req, &[ENOENT, EINVAL])
    }

    fn detach(&mut self, ifindex: u32, dir: Direction) -> io::Result<()> {
        send(&entry_delete(ifindex, dir), &[ENOENT])?;
        self.flush(ifindex, dir, ACL_CHAIN_A)?;
        self.flush(ifindex, dir, ACL_CHAIN_B)
    }

    fn counters(&mut self, ifindex: u32, dir: Direction, chain: u32) -> io::Result<Vec<Counter>> {
        Ok(counters_from(&dump(ifindex, dir.hook(), chain)?))
    }
}
