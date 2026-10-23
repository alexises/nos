//! Records every call and keeps a pretend entry per (ifindex, direction):
//! `--driver noop` and the tests.

use std::collections::BTreeMap;
use std::io;

use super::{Counter, Direction, Driver};
use crate::compile::Compiled;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Call {
    Install(u32, Direction, u32),
    Switch(u32, Direction, u32),
    Flush(u32, Direction, u32),
    Detach(u32, Direction),
}

#[derive(Debug, Default)]
pub struct NoopDriver {
    pub calls: Vec<Call>,
    /// What `live_chain` reports; `switch`/`detach` keep it current.
    pub live: BTreeMap<(u32, Direction), u32>,
    /// Makes the next `install` fail (a kernel refusal).
    pub fail_install: bool,
    /// What `counters` reports per (ifindex, direction), whatever the chain.
    pub counts: BTreeMap<(u32, Direction), Vec<Counter>>,
    /// Makes `counters` fail (the device vanished).
    pub fail_counters: bool,
}

impl Driver for NoopDriver {
    fn live_chain(&mut self, ifindex: u32, dir: Direction) -> io::Result<Option<u32>> {
        Ok(self.live.get(&(ifindex, dir)).copied())
    }

    fn install(
        &mut self,
        ifindex: u32,
        dir: Direction,
        chain: u32,
        _acl: &Compiled,
    ) -> io::Result<()> {
        self.calls.push(Call::Install(ifindex, dir, chain));
        if std::mem::take(&mut self.fail_install) {
            return Err(io::Error::other("refused"));
        }
        Ok(())
    }

    fn switch(&mut self, ifindex: u32, dir: Direction, chain: u32) -> io::Result<()> {
        self.calls.push(Call::Switch(ifindex, dir, chain));
        self.live.insert((ifindex, dir), chain);
        Ok(())
    }

    fn flush(&mut self, ifindex: u32, dir: Direction, chain: u32) -> io::Result<()> {
        self.calls.push(Call::Flush(ifindex, dir, chain));
        Ok(())
    }

    fn detach(&mut self, ifindex: u32, dir: Direction) -> io::Result<()> {
        self.calls.push(Call::Detach(ifindex, dir));
        self.live.remove(&(ifindex, dir));
        Ok(())
    }

    fn counters(&mut self, ifindex: u32, dir: Direction, _chain: u32) -> io::Result<Vec<Counter>> {
        if self.fail_counters {
            return Err(io::Error::other("gone"));
        }
        Ok(self
            .counts
            .get(&(ifindex, dir))
            .cloned()
            .unwrap_or_default())
    }
}
