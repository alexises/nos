use std::net::IpAddr;
use std::path::{Path, PathBuf};

use nos_daemon::ipc::{self, IpcError};
use nos_proto::{PrefixRoutes, RibEvent, RibRequest, Role};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum RibClientError {
    #[error("could not connect to nos-ribd at {path}: {source}")]
    Connect {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("connection to nos-ribd closed unexpectedly")]
    ConnectionClosed,
    #[error("i/o error talking to nos-ribd: {0}")]
    Io(#[from] std::io::Error),
    #[error("nos-ribd reported an error: {0}")]
    Daemon(String),
}

async fn ask(rib_socket: &Path, req: RibRequest) -> Result<RibEvent, RibClientError> {
    ipc::request(rib_socket, Role::Ribd, req)
        .await
        .map_err(|e| match e {
            IpcError::Connect { path, source } => RibClientError::Connect { path, source },
            IpcError::Io(e) => RibClientError::Io(e),
            IpcError::Closed => RibClientError::ConnectionClosed,
        })
}

/// Fetches the whole table: every prefix, each with its full candidate list
/// ordered best to worst, prefixes in ascending CIDR order.
pub async fn get_routes(rib_socket: &Path) -> Result<Vec<PrefixRoutes>, RibClientError> {
    match ask(rib_socket, RibRequest::GetRoutes).await? {
        RibEvent::Routes(routes) => Ok(routes),
        RibEvent::Error(msg) => Err(RibClientError::Daemon(msg)),
        _ => Err(RibClientError::Daemon(
            "unexpected event in reply to GetRoutes".to_string(),
        )),
    }
}

/// The table's VPN label (`None` without `vpn`, or from an older daemon
/// that does not know the request).
pub async fn get_vpn_label(rib_socket: &Path) -> Option<u32> {
    match ask(rib_socket, RibRequest::GetVpnLabel).await {
        Ok(RibEvent::VpnLabel(label)) => label,
        _ => None,
    }
}

/// Longest-prefix-match lookup for one destination address. `Ok(None)` means
/// no configured prefix covers `addr` (no default route).
pub async fn lookup(
    rib_socket: &Path,
    addr: IpAddr,
) -> Result<Option<PrefixRoutes>, RibClientError> {
    match ask(rib_socket, RibRequest::Lookup { addr }).await? {
        RibEvent::Match(routes) => Ok(Some(routes)),
        RibEvent::NoMatch => Ok(None),
        RibEvent::Error(msg) => Err(RibClientError::Daemon(msg)),
        _ => Err(RibClientError::Daemon(
            "unexpected event in reply to Lookup".to_string(),
        )),
    }
}
