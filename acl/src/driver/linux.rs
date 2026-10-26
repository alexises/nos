//! `nos-tc` against the real kernel. Coverage-excluded like every
//! `driver/linux.rs`; the requests themselves are built and tested in
//! `driver/mod.rs`, and `tests/kernel.rs` plus the `acl` e2e phase run this.

use std::collections::BTreeMap;
use std::io;

use nos_tc::{dump, psample, send, Hook, Protocol, Request};

use super::{
    chain_requests, check_log, counters_from, entry_delete, entry_request, exit_request,
    flowspec_counters_from, flowspec_delete, flowspec_prios_from, flowspec_requests, live_from,
    Counter, Direction, Driver, ACL_CHAIN_A, ACL_CHAIN_B,
};
use crate::compile::Compiled;
use crate::flowspec::{Lowered, EXIT_CHAIN};

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
        // Checked after the install, whose `sample` action loaded psample;
        // the idle chain is not live yet, the engine flushes it on `Err`.
        if acl.logs() {
            check_log(&psample()?)?;
        }
        Ok(())
    }

    fn switch(
        &mut self,
        ifindex: u32,
        dir: Direction,
        chain: u32,
        old: Option<u32>,
    ) -> io::Result<()> {
        // The exit filter first, the entry last: the entry swap is the one
        // commit point, so a failure before it leaves the old chain live.
        send(&exit_request(ifindex, dir, chain), &[])?;
        if let Err(e) = send(&entry_request(ifindex, dir, chain), &[]) {
            if let Some(old) = old {
                let _ = send(&exit_request(ifindex, dir, old), &[]);
            }
            return Err(e);
        }
        Ok(())
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
        self.flush(ifindex, dir, EXIT_CHAIN)?;
        self.flush(ifindex, dir, ACL_CHAIN_A)?;
        self.flush(ifindex, dir, ACL_CHAIN_B)
    }

    fn counters(&mut self, ifindex: u32, dir: Direction, chain: u32) -> io::Result<Vec<Counter>> {
        Ok(counters_from(&dump(ifindex, dir.hook(), chain)?))
    }

    fn flowspec_set(
        &mut self,
        ifindex: u32,
        prio: u16,
        rule: Option<(u32, &Lowered)>,
    ) -> io::Result<()> {
        let clear = |prio| {
            for p in [Protocol::Ip, Protocol::Ipv6] {
                send(&flowspec_delete(ifindex, prio, p), &[ENOENT, EINVAL])?;
            }
            Ok::<(), io::Error>(())
        };
        send(&Request::Clsact { ifindex }, &[EEXIST])?;
        clear(prio)?;
        let Some((cookie, rule)) = rule else {
            return Ok(());
        };
        for req in flowspec_requests(ifindex, prio, cookie, rule) {
            if let Err(e) = send(&req, &[]) {
                // Never leave half a rule installed.
                let _ = clear(prio);
                return Err(e);
            }
        }
        Ok(())
    }

    fn flowspec_prios(&mut self, ifindex: u32) -> io::Result<Vec<u16>> {
        Ok(flowspec_prios_from(&dump(ifindex, Hook::Ingress, 0)?))
    }

    fn flowspec_counters(&mut self, ifindex: u32) -> io::Result<BTreeMap<u16, (u64, u64)>> {
        Ok(flowspec_counters_from(&dump(ifindex, Hook::Ingress, 0)?))
    }
}
