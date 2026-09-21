//! The watchdog as certificate authority: one ephemeral CA per watchdog run,
//! a fresh leaf identity for every child it spawns (`supervisor`), the
//! public trust anchor published as `ca.crt`, and user certificates issued
//! at login (`broker`).
//!
//! There are two CAs, because the two transports have different audiences: the
//! IPC CA (ML-DSA-65, quantum-safe authentication) for daemons and `nos`, and
//! the REST CA (ECDSA P-256, so browsers and stock clients can present a
//! certificate) for `nos-restd`'s TCP listener and its clients. A REST
//! certificate never opens an IPC socket, and vice versa.
//!
//! The CA keys exist only in this process's memory. A watchdog restart
//! re-keys everything, which costs nothing: every child is restarted with it.

use std::io;
use std::net::IpAddr;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use nos_pki::{Bundle, Ca, Identity, KeyAlg, PeerId};
use nos_proto::Role;
use tokio::sync::watch;
use tokio::task::JoinHandle;
use tracing::{info, warn};

pub struct Pki {
    ca: Ca,
    rest_ca: Ca,
    /// The watchdog's own identity, for its config subscriptions, log
    /// forwarding and the broker socket. Rotated by `spawn_self_rotation`.
    pub identity: Identity,
    /// How long a daemon's certificate is valid…
    pub leaf_lifetime: Duration,
    /// …and how often a fresh one is pushed down its stdin.
    pub rotate_every: Duration,
    /// How long a logged-in user's certificate is valid.
    pub user_lifetime: Duration,
}

impl Pki {
    /// Creates both CAs, writes their public certificates to `<dir>/ca.crt`
    /// and `<dir>/rest-ca.crt` (world-readable: they only let a client
    /// recognise the watchdog), and issues the watchdog's own identity.
    pub fn start(
        dir: &Path,
        leaf_lifetime: Duration,
        rotate_every: Duration,
        user_lifetime: Duration,
    ) -> io::Result<Arc<Self>> {
        if rotate_every >= leaf_lifetime {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "--pki-rotate-every must be shorter than --pki-leaf-lifetime, or certificates expire before their replacement arrives",
            ));
        }
        let ca = Ca::new(KeyAlg::MlDsa65)?;
        let rest_ca = Ca::new(KeyAlg::EcdsaP256)?;
        std::fs::create_dir_all(dir)?;
        publish(dir, "ca.crt", &ca.cert_pem())?;
        publish(dir, "rest-ca.crt", &rest_ca.cert_pem())?;

        let identity = Identity::from_bundle(&ca.issue(&peer(Role::Watchdog, ""), leaf_lifetime)?)?;
        Ok(Arc::new(Self {
            ca,
            rest_ca,
            identity,
            leaf_lifetime,
            rotate_every,
            user_lifetime,
        }))
    }

    /// A fresh keypair and leaf for a daemon about to be (re)started, or due
    /// its next rotation.
    pub fn mint(&self, role: Role, name: &str) -> io::Result<Bundle> {
        self.ca.issue(&peer(role, name), self.leaf_lifetime)
    }

    /// Certifies the public key in a client's CSR as `user`. Returns the leaf
    /// certificate DER; the client keeps its private key.
    pub fn sign_user(&self, csr_der: &[u8], user: &str) -> io::Result<Vec<u8>> {
        self.ca
            .sign_csr(csr_der, &peer(Role::User, user), self.user_lifetime)
    }

    /// `sign_user`, from the REST CA: the certificate a REST client presents
    /// to `nos-restd` (a different trust domain from IPC).
    pub fn sign_rest_user(&self, csr_der: &[u8], user: &str) -> io::Result<Vec<u8>> {
        self.rest_ca
            .sign_csr(csr_der, &peer(Role::User, user), self.user_lifetime)
    }

    /// The listener certificate for `nos-restd`, and the REST CA's own
    /// certificate — the trust anchor it verifies client certificates against.
    pub fn sign_rest_server(
        &self,
        csr_der: &[u8],
        addresses: &[IpAddr],
    ) -> io::Result<(Vec<u8>, Vec<u8>)> {
        let cert = self
            .rest_ca
            .sign_server_csr(csr_der, addresses, self.leaf_lifetime)?;
        Ok((cert, self.rest_ca.cert_der().to_vec()))
    }

    /// Keeps the watchdog's own identity from expiring, the way
    /// `supervisor` does for each child.
    pub fn spawn_self_rotation(
        self: &Arc<Self>,
        mut shutdown: watch::Receiver<bool>,
    ) -> JoinHandle<()> {
        let pki = self.clone();
        tokio::spawn(async move {
            loop {
                tokio::select! {
                    () = tokio::time::sleep(pki.rotate_every) => {}
                    _ = shutdown.changed() => return,
                }
                match pki
                    .mint(Role::Watchdog, "")
                    .and_then(|b| pki.identity.update(&b))
                {
                    Ok(()) => info!(peer = ?pki.identity.peer(), "ipc identity rotated"),
                    Err(e) => warn!(error = %e, "failed to rotate the watchdog's own identity"),
                }
            }
        })
    }
}

/// Write-then-rename so a client never reads half a certificate.
fn publish(dir: &Path, name: &str, pem: &str) -> io::Result<()> {
    let (tmp, dest) = (dir.join(format!(".{name}.tmp")), dir.join(name));
    std::fs::write(&tmp, pem)?;
    std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(0o644))?;
    std::fs::rename(&tmp, &dest)
}

fn peer(role: Role, name: &str) -> PeerId {
    PeerId::new(role.as_str(), name)
}
