//! What the core asks of its host (the daemon, #327, or the test simulator).

use crate::bpdu::Bpdu;
use crate::machines::Role;
use crate::vector::BridgeId;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PortState {
    Discarding,
    Learning,
    Forwarding,
}

/// Plain facts for the host to log; no formatting here.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Event {
    RoleChanged {
        port: usize,
        from: Role,
        to: Role,
    },
    RootChanged {
        root: BridgeId,
        root_port: Option<usize>,
    },
    /// PPM changed what `port` transmits (13.31 `sendRSTP`): `rstp` false is
    /// the 802.1D Config/TCN dialect.
    ProtocolMigrated {
        port: usize,
        rstp: bool,
    },
    /// `run` hit its pass cap: a machine bug, the state is left as it was.
    NotQuiescent,
}

/// Drained by the host after every call that can produce them
/// ([`crate::bridge::Bridge::take_actions`]).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Action {
    Transmit {
        port: usize,
        bpdu: Bpdu,
    },
    SetPortState {
        port: usize,
        state: PortState,
    },
    /// Flush the learned MACs of this port (`fdbFlush`, performed synchronously).
    FlushFdb {
        port: usize,
    },
    Log(Event),
}
