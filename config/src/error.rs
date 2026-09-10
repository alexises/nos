use thiserror::Error;

#[derive(Debug, Error)]
pub enum ConfigError {
    #[error("validation failed:\n{0}")]
    Validation(#[from] garde::Report),
    #[error("no candidate config to commit")]
    NoCandidate,
}
