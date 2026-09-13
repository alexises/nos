//! Default addresses for the two sockets that stay fixed rather than being
//! resolved dynamically via the watchdog broker: `nos-configd`'s own socket
//! (which the watchdog itself is told about via `--config-socket` and never
//! resolves) and `nos-watchdogd`'s own broker socket (the one address every
//! other client must still know up front in order to resolve everything
//! else).

pub const DEFAULT_CONFIG_SOCKET: &str = "/run/nos/config.sock";
pub const DEFAULT_WATCHDOG_SOCKET: &str = "/run/nos/watchdog.sock";
