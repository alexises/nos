use serde::{Deserialize, Serialize};

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
    CommitTransaction { name: String },
    /// Deletes a named transaction without touching the running config.
    DiscardTransaction { name: String },
    /// One-shot: fetch the daemon-authored documentation for one operation
    /// (see `nos_proto::docs::CommandDoc`), so any client can show
    /// consistent help text without hardcoding its own copy. Scoped to a
    /// single `Topic` rather than the whole catalog, so a client only ever
    /// pays for the docs it actually displays.
    Describe { topic: Topic },
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
}
