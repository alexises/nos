use serde::{Deserialize, Serialize};

/// Identifies *what an operation does*, independent of any one client's
/// concrete invocation syntax. One entry per server-meaningful operation —
/// mirrors `Request` variants and `ConfigOp`/`BgpInstanceOp` variants that
/// have a client-reachable counterpart. Purely client-local mechanics (e.g.
/// a shell's own navigation commands) have no `Topic` — they're not
/// something `nos-config` has any notion of.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum Topic {
    /// `Request::Get`
    ShowRunningConfig,
    /// `Request::Save`
    Save,
    /// `Request::OpenTransaction`
    OpenTransaction,
    /// `Request::GetTransaction`
    GetTransaction,
    /// `Request::CommitTransaction`
    CommitTransaction,
    /// `Request::DiscardTransaction`
    DiscardTransaction,
    /// `ConfigOp::BgpInstance(BgpInstanceOp::Ensure)`
    EnsureBgpInstance,
    /// `ConfigOp::BgpInstance(BgpInstanceOp::SetAsn)`
    SetBgpInstanceAsn,
    /// `ConfigOp::BgpInstance(BgpInstanceOp::SetRouterId)`
    SetBgpInstanceRouterId,
    /// `ConfigOp::BgpInstance(BgpInstanceOp::Delete)`
    DeleteBgpInstance,
    /// `ConfigOp::SetHostname`
    SetHostname,
}

/// What an operation does, authored by `nos-config` and served to any client
/// over IPC (`Request::Describe` / `Event::Descriptions`). Deliberately has
/// no "usage" field — exact invocation syntax (argument order, keywords) is
/// specific to each client and doesn't belong here.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CommandDoc {
    pub topic: Topic,
    /// One-line description.
    pub summary: String,
    /// Fuller explanation, including caveats or side effects.
    pub detail: String,
}
