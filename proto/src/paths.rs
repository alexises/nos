//! Default addresses for the sockets that stay fixed rather than being
//! resolved dynamically via the watchdog broker: `nos-configd`'s own socket
//! (which the watchdog itself is told about via `--config-socket` and never
//! resolves), `nos-logd`'s own socket (which the watchdog similarly passes
//! directly, via `--log-socket`, to every other process it spawns — see
//! root `CLAUDE.md`'s "Process supervision" section — rather than having
//! each one resolve it through the broker), and `nos-watchdogd`'s own broker
//! socket (the one address every other client must still know up front in
//! order to resolve everything else).

pub const DEFAULT_CONFIG_SOCKET: &str = "/run/nos/config.sock";
pub const DEFAULT_LOG_SOCKET: &str = "/run/nos/log.sock";
pub const DEFAULT_WATCHDOG_SOCKET: &str = "/run/nos/watchdog.sock";
