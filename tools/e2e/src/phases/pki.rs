//! IPC transport security: every daemon connection is mutually authenticated
//! TLS, `nos-watchdogd` is the certificate authority, and humans log in.
//!
//! Every other phase is already an implicit test of the happy path — none of
//! them could pass if a daemon couldn't authenticate to another — so these
//! only assert what they can't: who each daemon believes it is, that login
//! accepts the right password and refuses the wrong one, and that hot
//! rotation really keeps long-lived daemons connectable after their first
//! certificate has expired.

use anyhow::{bail, Context};

use super::bgp;
use crate::consts::*;
use crate::router::{log, A};
use crate::world::World;

/// A daemon's log line for the identity it was handed: `role` is what its
/// certificate asserts, `name` the instance/table (empty for singletons).
fn identity(message: &str, fields: &str, role: &str, name: &str) -> String {
    format!("{message} {fields}peer=Some(PeerId {{ role: \"{role}\", name: \"{name}\" }})")
}

/// Runs `nos-provision` on router-a as `password`, the way an operator or the
/// bench would: it must log in before it may touch `nos-configd`.
async fn provision_as(w: &World, password: &str) -> anyhow::Result<(i64, String)> {
    // The tool builds its op list from the same flags every provisioning
    // starts with, so give it router-a's own (an idempotent re-apply).
    let mut cmd = vec![
        "nos-provision".to_string(),
        "--config-socket".to_string(),
        "/run/nos/config.sock".to_string(),
        "--login-user".to_string(),
        E2E_USER.to_string(),
        "--login-password".to_string(),
        password.to_string(),
    ];
    cmd.extend(A.base_flags());
    let cmd: Vec<&str> = cmd.iter().map(String::as_str).collect();
    w.dock.exec("router-a", &cmd).await
}

/// Each daemon holds the identity the watchdog minted for it, login works, and
/// a wrong password is refused. Requires `up` (and `established`) to have run.
pub async fn pki(w: &mut World) -> anyhow::Result<()> {
    let a = w.a()?;
    a.wait("ipc certificate authority ready").await?;
    a.wait(&identity("ipc identity loaded", "", "configd", ""))
        .await?;
    a.wait(&identity("nos-ribd starting", "table=rt1 ", "ribd", "rt1"))
        .await?;
    // Whatever the instance is called, its certificate must carry that name.
    a.wait(&identity("nos-bgpd starting", "instance=.* ", "bgpd", ".*"))
        .await?;

    log("logging in with the wrong password (must be refused)");
    let rejected = a.count(&format!("login rejected user={E2E_USER}"));
    let (code, out) = provision_as(w, "not-the-password").await?;
    if code == 0 || !out.contains("login refused") {
        bail!("a wrong password must be refused, got exit {code}: {out}");
    }
    a.wait_new(&format!("login rejected user={E2E_USER}"), rejected, 15)
        .await?;

    log("logging in with the right password, then editing config as that user");
    let accepted = a.count(&format!("login accepted user={E2E_USER}"));
    let (code, out) = provision_as(w, E2E_PASSWORD).await?;
    if code != 0 || !out.contains("provisioning complete") {
        bail!("login with the right password should provision, got exit {code}: {out}");
    }
    a.wait_new(&format!("login accepted user={E2E_USER}"), accepted, 15)
        .await
}

/// Hot rotation: with certificates that expire in seconds, wait past a whole
/// lifetime, then force fresh handshakes between long-lived processes. Each
/// only succeeds if the dialing daemon had rotated to a certificate that isn't
/// the (long expired) one it was started with.
pub async fn pki_rotation(w: &mut World) -> anyhow::Result<()> {
    let lifetime = format!("--pki-leaf-lifetime={PKI_LEAF_LIFETIME_SECS}");
    let rotate = format!("--pki-rotate-every={PKI_ROTATE_EVERY_SECS}");
    w.up(&[&lifetime, &rotate]).await?;
    bgp::established(w).await?;

    let a = w.a()?;
    a.wait_new("ipc identity rotated", 0, PKI_ROTATE_EVERY_SECS * 3)
        .await?;

    let wait = PKI_LEAF_LIFETIME_SECS + 10;
    log(format!(
        "waiting {wait}s: every certificate the daemons started with expires in {PKI_LEAF_LIFETIME_SECS}s"
    ));
    tokio::time::sleep(std::time::Duration::from_secs(wait)).await;

    // nos-bgpd is long-lived, so its handshake with the *restarted* nos-ribd
    // uses whatever certificate it holds now — which is only valid if the
    // rotation reached it. It only notices its push connection died when it
    // next has something to write (an existing quirk of the push client, not
    // of TLS: with no route change it never writes), so give it a route change:
    // router-b advertises a prefix to router-a.
    let a = w.a()?;
    let snapshot = "sent initial bgp route snapshot to nos-ribd";
    let (snapshots, kernel_routes, ribds) = (
        a.count(snapshot),
        a.count("added route"),
        a.count("nos-ribd starting"),
    );
    log("killing router-a's nos-ribd; the watchdog restarts it with a fresh identity");
    w.dock
        .kill_process("router-a", "nos-ribd")
        .await
        .context("killing nos-ribd")?;
    a.wait_new("nos-ribd starting", ribds, 30).await?;

    // REST (a per-request client of nos-configd) provisions router-b with a
    // certificate minted a lifetime ago and rotated since; router-a's nos-bgpd
    // then learns the route, fails to write it to the dead socket, reconnects to
    // the new nos-ribd with its rotated identity, and the route lands in the
    // kernel — the whole path, on rotated identities.
    w.b()?.provision(&bgp::redistribute()).await?;
    let a = w.a()?;
    a.wait(&bgp::learned()).await?;
    a.wait_new(snapshot, snapshots, 60).await?;
    a.wait_new("added route", kernel_routes, 60).await
}
