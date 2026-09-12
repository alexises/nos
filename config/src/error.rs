use std::path::PathBuf;

use thiserror::Error;

#[derive(Debug, Error)]
pub enum ConfigError {
    #[error("validation failed:\n{0}")]
    Validation(#[from] garde::Report),
    #[error("no candidate config to commit")]
    NoCandidate,
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
