use std::path::{Path, PathBuf};

use nos_daemon::ipc::{self, IpcError};
use nos_proto::{InterfaceEvent, InterfaceRequest, InterfaceStatus, PortAggregateStatus, Role};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum InterfaceClientError {
    #[error("could not connect to nos-interfaced at {path}: {source}")]
    Connect {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("connection to nos-interfaced closed unexpectedly")]
    ConnectionClosed,
    #[error("i/o error talking to nos-interfaced: {0}")]
    Io(#[from] std::io::Error),
    #[error("nos-interfaced reported an error: {0}")]
    Daemon(String),
}

async fn ask(
    interface_socket: &Path,
    req: InterfaceRequest,
) -> Result<InterfaceEvent, InterfaceClientError> {
    ipc::request(interface_socket, Role::Interfaced, req)
        .await
        .map_err(|e| match e {
            IpcError::Connect { path, source } => InterfaceClientError::Connect { path, source },
            IpcError::Io(e) => InterfaceClientError::Io(e),
            IpcError::Closed => InterfaceClientError::ConnectionClosed,
            IpcError::Timeout(_) => InterfaceClientError::Io(std::io::ErrorKind::TimedOut.into()),
        })
}

/// Fetches every configured interface's reconciled status.
pub async fn get_interfaces(
    interface_socket: &Path,
) -> Result<Vec<InterfaceStatus>, InterfaceClientError> {
    match ask(interface_socket, InterfaceRequest::GetInterfaces).await? {
        InterfaceEvent::Interfaces(statuses) => Ok(statuses),
        _ => Err(InterfaceClientError::Daemon(
            "unexpected event in reply to GetInterfaces".to_string(),
        )),
    }
}

/// Fetches one named interface's reconciled status. `Ok(None)` means no such
/// interface is configured.
pub async fn get_interface(
    interface_socket: &Path,
    name: &str,
) -> Result<Option<InterfaceStatus>, InterfaceClientError> {
    match ask(
        interface_socket,
        InterfaceRequest::GetInterface {
            name: name.to_string(),
        },
    )
    .await?
    {
        InterfaceEvent::Interface(status) => Ok(Some(status)),
        InterfaceEvent::NotFound => Ok(None),
        _ => Err(InterfaceClientError::Daemon(
            "unexpected event in reply to GetInterface".to_string(),
        )),
    }
}

/// Fetches every configured port aggregate's reconciled status.
pub async fn get_port_aggregates(
    interface_socket: &Path,
) -> Result<Vec<PortAggregateStatus>, InterfaceClientError> {
    match ask(interface_socket, InterfaceRequest::GetPortAggregates).await? {
        InterfaceEvent::PortAggregates(statuses) => Ok(statuses),
        _ => Err(InterfaceClientError::Daemon(
            "unexpected event in reply to GetPortAggregates".to_string(),
        )),
    }
}

/// Fetches one named port aggregate's reconciled status. `Ok(None)` means no
/// such aggregate is configured.
pub async fn get_port_aggregate(
    interface_socket: &Path,
    name: &str,
) -> Result<Option<PortAggregateStatus>, InterfaceClientError> {
    match ask(
        interface_socket,
        InterfaceRequest::GetPortAggregate {
            name: name.to_string(),
        },
    )
    .await?
    {
        InterfaceEvent::PortAggregate(status) => Ok(Some(status)),
        InterfaceEvent::NotFound => Ok(None),
        _ => Err(InterfaceClientError::Daemon(
            "unexpected event in reply to GetPortAggregate".to_string(),
        )),
    }
}
