//! One router container, provisioned and observed purely over its REST API.

use std::time::Duration;

use anyhow::{bail, Context};
use clap::Parser;
use nos_proto::Config;
use nos_provision::{build_ops, Args};
use reqwest::Method;

use crate::consts::*;
use crate::docker::{ContainerSpec, Dock};
use crate::logs::Logs;
use crate::rest::Rest;

pub fn log(msg: impl AsRef<str>) {
    eprintln!("[nos-e2e] {}", msg.as_ref());
}

/// Who a router is: its container name, address, and BGP identity toward its
/// (single) default peer. Phases with a different topology pass their own flags.
#[derive(Clone, Copy)]
pub struct Id {
    pub name: &'static str,
    pub ip: &'static str,
    pub asn: u32,
    pub rid: &'static str,
    pub peer_ip: &'static str,
    pub remote_as: u32,
}

pub const A: Id = Id {
    name: "router-a",
    ip: IP_A,
    asn: ASN_A,
    rid: RID_A,
    peer_ip: IP_B,
    remote_as: ASN_B,
};
pub const B: Id = Id {
    name: "router-b",
    ip: IP_B,
    asn: ASN_B,
    rid: RID_B,
    peer_ip: IP_A,
    remote_as: ASN_A,
};
/// router-c as `ospf-dr`/`route-server` provision it: its own AS, peering router-a.
pub const C: Id = Id {
    name: "router-c",
    ip: IP_C,
    asn: ASN_C,
    rid: RID_C,
    peer_ip: IP_A,
    remote_as: ASN_A,
};
/// The `rest` phase's throwaway router.
pub const R: Id = Id {
    name: "router-r",
    ip: IP_R,
    asn: ASN_C,
    rid: RID_C,
    peer_ip: IP_A,
    remote_as: ASN_A,
};

impl Id {
    /// The flags every provisioning starts from: one address on eth0 in `rt1`,
    /// one BGP instance/peer-group/peer.
    pub fn base_flags(&self) -> Vec<String> {
        strings(&[
            "--address",
            &format!("{}/24", self.ip),
            "--asn",
            &self.asn.to_string(),
            "--router-id",
            self.rid,
            "--remote-as",
            &self.remote_as.to_string(),
            "--peer",
            self.peer_ip,
        ])
    }
}

/// Connect-retry for every peer-group the harness configures. The 120s default
/// leaves both sides Idle that long whenever a fresh start or a config change
/// loses RFC 4271 §6.8 collision resolution; a few seconds makes the retry —
/// and so every "session (re-)established" wait — fast.
const CONNECT_RETRY_SECS: &str = "3";

fn with_fast_retry(flags: &mut Vec<String>) {
    flags.extend(strings(&["--connect-retry-time", CONNECT_RETRY_SECS]));
}

pub fn strings(s: &[&str]) -> Vec<String> {
    s.iter().map(|x| (*x).to_string()).collect()
}

fn parse(flags: &[String]) -> anyhow::Result<Args> {
    Args::try_parse_from(std::iter::once("nos-provision".to_string()).chain(flags.iter().cloned()))
        .context("parsing provisioning flags")
}

pub struct Router {
    pub id: Id,
    pub logs: Logs,
    pub rest: Rest,
}

impl Router {
    pub fn name(&self) -> &'static str {
        self.id.name
    }

    /// Attaches to a router that is already running (its REST API is pinned).
    /// The REST CA is read out of the container — the one trusted channel to
    /// it — since a client verifies the API against exactly that.
    pub async fn attach(dock: &Dock, id: Id) -> anyhow::Result<Self> {
        let ca = Self::fetch_rest_ca(dock, id.name).await?;
        let rest = Rest::new(id.ip, REST_PORT, ca);
        Ok(Self {
            id,
            logs: Logs::follow(rest.clone()),
            rest,
        })
    }

    /// `nos-watchdogd` publishes `rest-ca.crt` as it starts; a container that
    /// was only just started may not have it yet.
    async fn fetch_rest_ca(dock: &Dock, container: &str) -> anyhow::Result<Vec<u8>> {
        for _ in 0..60 {
            if let Ok((0, pem)) = dock.exec(container, &["cat", REST_CA_PATH]).await {
                if pem.contains("BEGIN CERTIFICATE") {
                    return Ok(pem.into_bytes());
                }
            }
            tokio::time::sleep(Duration::from_secs(1)).await;
        }
        bail!("{container}: {REST_CA_PATH} never appeared")
    }

    /// Starts `id`'s container from a *seeded* config — `seed_flags` plus the
    /// `rest-api` pin, written to `/var/lib/nos/config.yaml` before boot,
    /// because REST only exists once the config pins it — and waits until the
    /// API answers. `watchdog_args` go straight to `nos-watchdogd`.
    pub async fn start(
        dock: &Dock,
        id: Id,
        seed_flags: Option<Vec<String>>,
        watchdog_args: &[&str],
    ) -> anyhow::Result<Self> {
        let mut flags = seed_flags.unwrap_or_else(|| id.base_flags());
        flags.extend(strings(&[
            "--user",
            &format!("{E2E_USER}={E2E_PASSWORD}"),
            "--rest-api-address",
            id.ip,
            "--rest-api-port",
            &REST_PORT.to_string(),
        ]));
        with_fast_retry(&mut flags);
        let mut config = Config::default();
        for op in build_ops(&parse(&flags)?)? {
            op.apply(&mut config)
                .map_err(|e| anyhow::anyhow!("seeding {}: {e}", id.name))?;
        }
        let yaml = serde_yaml::to_string(&config)?;

        // A big log buffer, so the backlog re-read after a reconnect is complete.
        let mut cmd = strings(&["--logd-arg=--capacity=200000"]);
        cmd.extend(strings(watchdog_args));
        log(format!("starting {} at {}", id.name, id.ip));
        dock.start(&ContainerSpec {
            name: id.name,
            network: NET,
            ip: id.ip,
            cmd,
            seed: Some(("config.yaml", yaml.into_bytes())),
        })
        .await?;

        let router = Self::attach(dock, id).await?;
        router.wait_ready().await?;
        router.logs.settle().await;
        Ok(router)
    }

    pub async fn wait_ready(&self) -> anyhow::Result<()> {
        log(format!("waiting for {}'s REST API", self.name()));
        for _ in 0..120 {
            if let Ok((200, _)) = self.rest(Method::GET, "/v1/config", None).await {
                return Ok(());
            }
            tokio::time::sleep(Duration::from_secs(1)).await;
        }
        bail!(
            "{}: REST API never came up on {}",
            self.name(),
            self.rest.base()
        )
    }

    /// One HTTPS call presenting the harness's own client certificate;
    /// `(status, body)`. Only a transport failure is an `Err`.
    pub async fn rest(
        &self,
        method: Method,
        path: &str,
        body: Option<&str>,
    ) -> anyhow::Result<(u16, String)> {
        let client = self.rest.client().await?;
        self.rest_with(&client, method, path, body).await
    }

    /// Like `rest`, over `client` — one presenting another certificate, or none
    /// (`Rest::anonymous`).
    pub async fn rest_with(
        &self,
        client: &reqwest::Client,
        method: Method,
        path: &str,
        body: Option<&str>,
    ) -> anyhow::Result<(u16, String)> {
        let mut req = client.request(method, format!("{}{path}", self.rest.base()));
        if let Some(b) = body {
            req = req
                .header("content-type", "application/json")
                .body(b.to_string());
        }
        let resp = req.send().await?;
        let status = resp.status().as_u16();
        Ok((status, resp.text().await?))
    }

    /// Like `rest`, but any status other than `want` is an error.
    pub async fn rest_expect(
        &self,
        method: Method,
        path: &str,
        body: Option<&str>,
        want: u16,
    ) -> anyhow::Result<String> {
        let (status, text) = self.rest(method.clone(), path, body).await?;
        if status != want {
            bail!(
                "{}: {method} {path} -> {status} (want {want}): {text}",
                self.name()
            );
        }
        Ok(text)
    }

    /// Applies one provisioning to the running config: open a transaction from
    /// the current config, edit it locally, `PUT` it back whole, commit.
    pub async fn provision<S: AsRef<str>>(&self, extra: &[S]) -> anyhow::Result<()> {
        let mut flags = self.id.base_flags();
        flags.extend(extra.iter().map(|s| s.as_ref().to_string()));
        self.provision_flags(&flags).await
    }

    /// Like `provision`, but with the complete flag list (for a phase whose
    /// base differs, e.g. a routed subinterface's own `--address`).
    pub async fn provision_flags(&self, flags: &[String]) -> anyhow::Result<()> {
        let mut flags = flags.to_vec();
        with_fast_retry(&mut flags);
        log(format!("provisioning {}: {}", self.name(), flags.join(" ")));
        let ops = build_ops(&parse(&flags)?)?;
        self.edit(|config| {
            for op in &ops {
                op.apply(config).map_err(|e| anyhow::anyhow!("{e}"))?;
            }
            Ok(())
        })
        .await
    }

    /// Runs `f` against the running config inside a REST transaction.
    pub async fn edit(
        &self,
        f: impl FnOnce(&mut Config) -> anyhow::Result<()>,
    ) -> anyhow::Result<()> {
        let tx = "/v1/transactions/e2e";
        // A leftover transaction (a failed commit keeps it) would be resumed.
        let _ = self.rest(Method::DELETE, tx, None).await;
        let opened = self
            .rest_expect(Method::POST, &format!("{tx}?base=current"), None, 201)
            .await?;
        let snapshot: serde_json::Value = serde_json::from_str(&opened)?;
        let mut config: Config = serde_json::from_value(snapshot["config"].clone())
            .context("decoding the transaction's config")?;
        f(&mut config)?;
        self.rest_expect(Method::PUT, tx, Some(&serde_json::to_string(&config)?), 200)
            .await?;
        self.rest_expect(Method::POST, &format!("{tx}/commit"), None, 200)
            .await
            .map(drop)
    }

    // --- logs ---

    pub fn count(&self, pattern: &str) -> usize {
        self.logs.count(pattern)
    }

    /// Waits (up to 60s) for the pattern to appear at all.
    pub async fn wait(&self, pattern: &str) -> anyhow::Result<()> {
        self.wait_new(pattern, 0, 60).await
    }

    /// Waits for a BGP session to be established (peer-groups retry every
    /// `CONNECT_RETRY_SECS`, so a collision costs seconds, not minutes).
    pub async fn established(&self) -> anyhow::Result<()> {
        self.wait_new("bgp session established", 0, 60).await
    }

    /// Waits for more than `baseline` matches of the BRE `pattern`.
    pub async fn wait_new(&self, pattern: &str, baseline: usize, secs: u64) -> anyhow::Result<()> {
        if self
            .logs
            .wait_over(pattern, baseline, Duration::from_secs(secs))
            .await
        {
            log(format!("{}: saw '{pattern}'", self.name()));
            Ok(())
        } else {
            bail!(
                "{}: no new log line matching '{pattern}' within {secs}s (baseline {baseline})",
                self.name()
            )
        }
    }

    /// Asserts no *new* match appears for `secs` seconds after `baseline`.
    pub async fn assert_quiet(
        &self,
        pattern: &str,
        baseline: usize,
        secs: u64,
    ) -> anyhow::Result<()> {
        tokio::time::sleep(Duration::from_secs(secs)).await;
        let now = self.count(pattern);
        if now > baseline {
            bail!(
                "{}: unexpected new log line matching '{pattern}' ({baseline} -> {now})",
                self.name()
            );
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The seed a router boots from: parses, builds, applies, pins REST on
    /// `rt1`, and survives the YAML round trip `nos-configd` loads it through.
    #[test]
    fn seed_config_pins_rest_and_round_trips() {
        let mut flags = A.base_flags();
        flags.extend(strings(&[
            "--rest-api-address",
            A.ip,
            "--rest-api-port",
            &REST_PORT.to_string(),
        ]));
        with_fast_retry(&mut flags);
        let mut config = Config::default();
        for op in build_ops(&parse(&flags).unwrap()).unwrap() {
            op.apply(&mut config).unwrap();
        }
        assert_eq!(
            config.bgp_instances[0].peer_groups[0].connect_retry_time,
            Some(3)
        );
        let rest = config.routing_tables[0].rest_api.as_ref().unwrap();
        assert_eq!(rest.address.to_string(), IP_A);
        assert_eq!(rest.port, REST_PORT);

        let yaml = serde_yaml::to_string(&config).unwrap();
        let back: Config = serde_yaml::from_str(&yaml).unwrap();
        assert_eq!(back.routing_tables.len(), 1);
        assert_eq!(back.bgp_instances[0].asn, ASN_A);
    }
}
