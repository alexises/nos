//! The watchdog as certificate authority: one ephemeral CA per watchdog run,
//! a fresh leaf identity for every child it spawns (`supervisor`), the
//! public trust anchor published as `ca.crt`, and user certificates issued
//! at login (`broker`).
//!
//! The CA key exists only in this process's memory. A watchdog restart
//! re-keys everything, which costs nothing: every child is restarted with it.

use std::io;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use nos_pki::{Bundle, Ca, Identity, PeerId};
use nos_proto::Role;
use tokio::sync::watch;
use tokio::task::JoinHandle;
use tracing::{info, warn};

pub struct Pki {
    ca: Ca,
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
    /// Creates the CA, writes its public certificate to `<dir>/ca.crt`
    /// (world-readable: it only lets a client recognise the watchdog), and
    /// issues the watchdog's own identity.
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
        let ca = Ca::new()?;
        std::fs::create_dir_all(dir)?;
        // Write-then-rename so a client never reads half a certificate.
        let (tmp, dest) = (dir.join(".ca.crt.tmp"), dir.join("ca.crt"));
        std::fs::write(&tmp, ca.cert_pem())?;
        std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(0o644))?;
        std::fs::rename(&tmp, &dest)?;

        let identity = Identity::from_bundle(&ca.issue(&peer(Role::Watchdog, ""), leaf_lifetime)?)?;
        Ok(Arc::new(Self {
            ca,
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

fn peer(role: Role, name: &str) -> PeerId {
    PeerId::new(role.as_str(), name)
}
