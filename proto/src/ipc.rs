use serde::{Deserialize, Serialize};

use crate::diff::{ConfigDiff, DiffScope};
use crate::docs::{CommandDoc, Topic};
use crate::ops::ConfigOp;
use crate::schema::Config;

/// Messages sent from a component client to the config daemon.
///
/// New variants must always be appended, never inserted — `postcard` encodes
/// enum variants by index, so reordering breaks wire compatibility with
/// already-built binaries.
#[derive(Debug, Serialize, Deserialize)]
pub enum Request {
    /// One-shot: receive the current full config snapshot then stop.
    Get,
    /// Start streaming: receive the current snapshot, then all future commits.
    Subscribe,
    /// Stop streaming updates (connection stays open for further requests).
    Unsubscribe,
    /// Persist the current running config to disk at the daemon's configured
    /// config-file path.
    Save,
    /// Opens a named transaction, creating it from `base` if it doesn't
    /// already exist, or resuming its current in-progress config unchanged
    /// (ignoring `base`) if it does.
    OpenTransaction { name: String, base: TransactionBase },
    /// Applies one edit to a named transaction's in-progress config.
    ApplyOp { name: String, op: ConfigOp },
    /// One-shot fetch of a named transaction's current in-progress config.
    GetTransaction { name: String },
    /// Validates a named transaction and, if valid, atomically promotes it
    /// to the running config, broadcasts the change to subscribers, and
    /// removes the transaction. If invalid, the transaction is left intact.
    /// `if_match` is an RFC 9110 §13.1.1 precondition: `Some(g)` refuses the
    /// commit unless the transaction's `generation` is still `g`; `None` is
    /// unconditional.
    CommitTransaction { name: String, if_match: Option<u64> },
    /// Deletes a named transaction without touching the running config.
    /// `if_match` as on `CommitTransaction`.
    DiscardTransaction { name: String, if_match: Option<u64> },
    /// One-shot: fetch the daemon-authored documentation for one operation
    /// (see `nos_proto::docs::CommandDoc`), so any client can show
    /// consistent help text without hardcoding its own copy. Scoped to a
    /// single `Topic` rather than the whole catalog, so a client only ever
    /// pays for the docs it actually displays.
    Describe { topic: Topic },
    /// One-shot: compute and return the structural difference between the
    /// running config and a named transaction's in-progress config.
    DiffTransaction { name: String },
    /// Start streaming diffs: an initial diff synthesized against an empty
    /// config (so a fresh subscriber sees every currently-configured item in
    /// `scopes` as `Added`), then one more `Event::Diff` per future commit
    /// that touches at least one requested scope — other commits are not
    /// sent at all.
    SubscribeDiff { scopes: Vec<DiffScope> },
    /// Watchdog-only compare-and-swap: replace `user`'s stored password hash
    /// `old` with the stronger re-hash `new` of the same password, straight
    /// in the running config (no transaction). Refused if `old` is no longer
    /// the stored hash or `new` is not a hash.
    UpgradePasswordHash {
        user: String,
        old: String,
        new: String,
    },
    /// Sets (`value` = `Some(json)`) or removes (`value` = `None`) the
    /// subsection of a named transaction's in-progress config addressed by
    /// `path` — see `nos_proto::config_path` for the path grammar. An empty
    /// `path` addresses the whole config. Like `ApplyOp`, never validates;
    /// replies with `Event::Transaction`. `if_match` as on
    /// `CommitTransaction`.
    SetTransactionPath {
        name: String,
        path: Vec<String>,
        value: Option<String>,
        if_match: Option<u64>,
    },
}

/// Messages sent from the config daemon to a component client.
#[derive(Debug, Serialize, Deserialize)]
pub enum Event {
    /// A full config snapshot — sent as the initial response to Get/Subscribe
    /// and on every subsequent commit while subscribed. This variant always
    /// carries the daemon's authoritative *running* config, never a
    /// transaction's in-progress state — see `Event::Transaction` for that.
    Config(Config),
    /// A human-readable error message from the daemon.
    Error(String),
    /// The running config was successfully persisted to disk, in reply to `Save`.
    Saved,
    /// A named transaction's current state, in reply to `OpenTransaction`,
    /// `ApplyOp`, or `GetTransaction`.
    Transaction(TransactionSnapshot),
    /// A named transaction was successfully committed, in reply to
    /// `CommitTransaction`.
    Committed,
    /// A named transaction was successfully discarded, in reply to
    /// `DiscardTransaction`.
    Discarded,
    /// One operation's documentation, in reply to `Describe`.
    Description(CommandDoc),
    /// The structural difference between the running config and a named
    /// transaction's in-progress config, in reply to `DiffTransaction`.
    Diff(ConfigDiff),
}

/// What a newly opened transaction's in-progress config should start from.
/// Ignored when `OpenTransaction` resumes an already-existing transaction.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum TransactionBase {
    /// Start from an empty `Config::default()`.
    Blank,
    /// Start from a clone of the current running config.
    Current,
}

/// A named transaction's current state, returned after `OpenTransaction`,
/// `ApplyOp`, and `GetTransaction`.
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TransactionSnapshot {
    pub name: String,
    pub config: Config,
    /// True once any `ApplyOp` has succeeded since the transaction was
    /// (re)created.
    pub dirty: bool,
    /// True if `OpenTransaction` attached to a pre-existing transaction
    /// rather than creating a new one.
    pub resumed: bool,
    /// Monotonic per-transaction edit counter: 0 when created, +1 on every
    /// successful `ApplyOp`/`SetTransactionPath`. The value an `if_match`
    /// precondition (and `nos-restd`'s `ETag`) compares against.
    pub generation: u64,
}
