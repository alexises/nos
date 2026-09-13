pub mod supervisor;

pub use supervisor::{supervise_one, BackoffPolicy, ProcessSpec};
