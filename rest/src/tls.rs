//! The listener's TLS identity: a server certificate `nos-watchdogd` issues for
//! the address being served (`IssueRestServerCert`), on a key generated here,
//! renewed at half its lifetime. The REST CA it chains to is also what client
//! certificates are verified against.

use std::net::IpAddr;
use std::sync::Arc;
use std::time::Duration;

use nos_pki::rest::RestServer;
use nos_pki::{generate_csr_for, KeyAlg};
use nos_proto::{WatchdogEvent, WatchdogRequest};
use tokio::task::JoinHandle;
use tracing::{info, warn};

use crate::ipc::Daemons;

/// How soon to retry a failed renewal.
const RETRY: Duration = Duration::from_secs(10);

struct Issued {
    cert: Vec<u8>,
    key: Vec<u8>,
    ca: Vec<u8>,
    lifetime: Duration,
}

async fn request(daemons: &Daemons, address: IpAddr) -> Result<Issued, String> {
    let (csr_der, key) = generate_csr_for(KeyAlg::EcdsaP256).map_err(|e| e.to_string())?;
    let reply = daemons
        .broker(WatchdogRequest::IssueRestServerCert {
            addresses: vec![address],
            csr_der,
        })
        .await
        .map_err(|e| format!("{e:?}"))?;
    match reply {
        WatchdogEvent::RestServerCert {
            cert_der,
            ca_der,
            lifetime_secs,
        } => Ok(Issued {
            cert: cert_der,
            key,
            ca: ca_der,
            lifetime: Duration::from_secs(lifetime_secs),
        }),
        other => Err(format!("unexpected reply {other:?}")),
    }
}

/// Gets a certificate for `address` and keeps it renewed until the returned
/// task is aborted.
pub async fn start(
    daemons: &Daemons,
    address: IpAddr,
) -> Result<(Arc<RestServer>, JoinHandle<()>), String> {
    let first = request(daemons, address).await?;
    let server = Arc::new(RestServer::new(&first.ca).map_err(|e| e.to_string())?);
    server
        .set_certificate(&first.cert, &first.key)
        .map_err(|e| e.to_string())?;
    let renewing = server.clone();
    let daemons = daemons.clone();
    let mut wait = first.lifetime / 2;
    let task = tokio::spawn(async move {
        loop {
            tokio::time::sleep(wait).await;
            wait = match request(&daemons, address).await {
                Ok(next) => match renewing.set_certificate(&next.cert, &next.key) {
                    Ok(()) => {
                        info!(%address, "rest listener certificate renewed");
                        next.lifetime / 2
                    }
                    Err(e) => {
                        warn!(error = %e, "ignoring a bad renewed listener certificate");
                        RETRY
                    }
                },
                Err(e) => {
                    warn!(error = %e, "could not renew the listener certificate, retrying");
                    RETRY
                }
            };
        }
    });
    Ok((server, task))
}
