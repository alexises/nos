use std::path::PathBuf;

use thiserror::Error;

#[derive(Debug, Error)]
pub enum ConfigError {
    #[error("validation failed:\n{0}")]
    Validation(#[from] garde::Report),
    #[error("refusing to commit: it would remove every user and lock everyone out")]
    NoUsersLeft,
    #[error("syslog server '{server}': tls trust-anchor is not a PEM certificate: {reason}")]
    SyslogTrustAnchor { server: String, reason: String },
    #[error("password hash upgrade refused: no such user, stale hash, or not a hash")]
    HashUpgradeRefused,
    #[error("no transaction named '{0}'")]
    TransactionNotFound(String),
    /// An `if_match` precondition (RFC 9110 §13.1.1) named a generation the
    /// transaction has moved past. `nos-restd` keys on the message prefix.
    #[error("precondition failed: transaction generation is {actual}, not {expected}")]
    PreconditionFailed { expected: u64, actual: u64 },
    #[error("edit failed: {0}")]
    Op(#[from] nos_proto::OpError),
    #[error("config path: {0}")]
    Path(#[from] nos_proto::config_path::PathError),
    #[error("invalid JSON body for config path: {0}")]
    Json(#[from] serde_json::Error),
    #[error("config persistence is not configured on this daemon (no --config-file set)")]
    PersistenceNotConfigured,
    #[error("IPC I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error("failed to read/write config file at {path}: {source}")]
    Persistence {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("failed to (de)serialize config: {0}")]
    Serialization(#[from] serde_yaml::Error),
}
