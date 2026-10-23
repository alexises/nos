//! `nos-acld`'s IPC query protocol — backs `show acl` and `GET /v1/acl`.
//! One-shot request/event pair framed by `IpcCodec`, resolved through the
//! broker (`ServiceRef::Acl`, a single instance), like `stp`.

use serde::{Deserialize, Serialize};

use crate::schema::AclAction;

/// Which way an ACL filters on its device.
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum AclDirection {
    /// `acl in`: packets arriving on the device.
    In,
    /// `acl out`: packets leaving the device.
    Out,
}

/// One device an ACL is installed on.
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct AclAttachment {
    /// The kernel device name (`eth1`, `eth1.100`, `bond3`).
    pub interface: String,
    /// The direction it filters.
    pub direction: AclDirection,
}

/// One user rule's counters, summed over every filter it compiled to and
/// every device the ACL is attached to.
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AclRuleStatus {
    /// The rule's name.
    pub name: String,
    /// What it does with a match.
    pub action: AclAction,
    /// `shadowed` (an earlier rule matches everything it does) or `trailing`
    /// (last rules equal to the default action): the optimiser gave the rule
    /// no filter, so its counters stay 0. `None` when it is installed.
    pub dropped: Option<String>,
    /// The priority level the rule's filters were packed into; `None` when
    /// dropped.
    pub level: Option<u32>,
    /// Packets matched.
    pub packets: u64,
    /// Bytes matched.
    pub bytes: u64,
}

/// One ACL: its compile shape, attachments and counters.
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AclStatus {
    /// The ACL's name.
    pub name: String,
    /// What a packet no rule matched gets.
    pub default_action: AclAction,
    /// Packets that hit the default action.
    pub default_packets: u64,
    /// Bytes that hit the default action.
    pub default_bytes: u64,
    /// Priority levels the compiled ACL uses.
    pub levels: u32,
    /// Kernel filters per attachment, the two default filters included.
    pub filters: u32,
    /// Every device it is installed on (empty: unattached, counters 0).
    pub attached: Vec<AclAttachment>,
    /// The rules, in order.
    pub rules: Vec<AclRuleStatus>,
}

/// Messages sent from a client to `nos-acld`'s IPC socket.
///
/// New variants must always be appended, never inserted — `postcard` encodes
/// enum variants by index.
#[derive(Debug, Serialize, Deserialize)]
pub enum AclRequest {
    /// One-shot: every ACL (`None`) or the named one; an unknown name gives
    /// an empty reply.
    Show {
        /// Restrict the reply to this ACL.
        name: Option<String>,
    },
}

/// Messages sent from `nos-acld` to a query client.
#[derive(Debug, Serialize, Deserialize)]
pub enum AclEvent {
    /// Reply with the ACLs, ordered by name.
    Acls(Vec<AclStatus>),
}
