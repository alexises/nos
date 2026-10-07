//! Default addresses for the sockets that stay fixed rather than being
//! resolved dynamically via the watchdog broker: `nos-configd`'s own socket
//! (which the watchdog itself is told about via `--config-socket` and never
//! resolves), `nos-logd`'s own socket (which the watchdog similarly passes
//! directly, via `--log-socket`, to every other process it spawns — see
//! `docs/architecture/supervision.md` — rather than having
//! each one resolve it through the broker), and `nos-watchdogd`'s own broker
//! socket (the one address every other client must still know up front in
//! order to resolve everything else).

pub const DEFAULT_CONFIG_SOCKET: &str = "/run/nos/config.sock";
pub const DEFAULT_LOG_SOCKET: &str = "/run/nos/log.sock";
pub const DEFAULT_WATCHDOG_SOCKET: &str = "/run/nos/watchdog.sock";

/// Where `nos-watchdogd` publishes the public trust anchor every IPC client
/// bootstraps from (`--pki-dir`). Public by design: it authenticates the
/// watchdog to a client, and grants nothing.
pub const DEFAULT_PKI_DIR: &str = "/run/nos/pki";
pub const DEFAULT_PKI_CA: &str = "/run/nos/pki/ca.crt";
