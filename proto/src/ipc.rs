use serde::{Deserialize, Serialize};

use crate::schema::Config;

/// Messages sent from a component client to the config daemon.
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
}

/// Messages sent from the config daemon to a component client.
#[derive(Debug, Serialize, Deserialize)]
pub enum Event {
    /// A full config snapshot — sent as the initial response to Get/Subscribe
    /// and on every subsequent commit while subscribed.
    Config(Config),
    /// A human-readable error message from the daemon.
    Error(String),
    /// The running config was successfully persisted to disk, in reply to `Save`.
    Saved,
}
