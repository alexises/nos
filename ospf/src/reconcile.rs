use std::path::PathBuf;
use std::time::Duration;

use futures::StreamExt;
use nos_proto::{DiffScope, Event};
use tokio::sync::watch;
use tracing::{info, warn};

use crate::config_client;

/// Fixed reconnect delay for the config subscription, matching every other
/// config-subscribing consumer in this codebase (`nos-bgp`/`nos-rib`/
/// `nos-interface`'s own `reconcile::RECONNECT_DELAY`).
const RECONNECT_DELAY: Duration = Duration::from_secs(1);

/// Runs until `shutdown` fires. Subscribes to `OspfInstances` diffs purely as
/// a resync trigger — the actual state always comes from a fresh
/// `fetch_config` call. This is a config-only skeleton (see `ospf/CLAUDE.md`):
/// there is no OSPF protocol logic yet, so a resync only ever logs what it
/// found.
pub async fn run(config_socket: PathBuf, instance: String, mut shutdown: watch::Receiver<bool>) {
    while !*shutdown.borrow() {
        match config_client::subscribe_diff(&config_socket, vec![DiffScope::OspfInstances]).await {
            Ok(mut reader) => {
                info!(instance = %instance, "connected to nos-configd diff stream");
                resync(&config_socket, &instance).await;
                loop {
                    tokio::select! {
                        event = reader.next() => match event {
                            Some(Ok(Event::Diff(_))) => {
                                resync(&config_socket, &instance).await;
                            }
                            Some(Ok(_)) => {}
                            Some(Err(e)) => {
                                warn!(error = %e, "error reading diff stream, reconnecting");
                                break;
                            }
                            None => {
                                warn!("diff stream closed, reconnecting");
                                break;
                            }
                        },
                        _ = shutdown.changed() => break,
                    }
                }
            }
            Err(e) => warn!(
                error = %e,
                socket = %config_socket.display(),
                "failed to connect to nos-configd"
            ),
        }

        if *shutdown.borrow() {
            break;
        }
        if wait_or_shutdown(RECONNECT_DELAY, &mut shutdown).await {
            break;
        }
    }

    info!(instance = %instance, "reconciliation loop stopped");
}

async fn resync(config_socket: &std::path::Path, instance: &str) {
    let cfg = match config_client::fetch_config(config_socket).await {
        Ok(cfg) => cfg,
        Err(e) => {
            warn!(error = %e, "failed to fetch running config, keeping previous state");
            return;
        }
    };

    match cfg.ospf_instances.iter().find(|i| i.name == instance) {
        Some(own) => {
            info!(
                instance = %instance,
                router_id = %own.router_id,
                routing_table = ?own.routing_table,
                area_count = own.areas.len(),
                "ospf instance config resolved"
            );
            for area in &own.areas {
                info!(
                    instance = %instance,
                    area = %area.area_id,
                    profile_count = area.profiles.len(),
                    "ospf area resolved"
                );
                for profile in &area.profiles {
                    let interfaces = attach_points_for(&cfg, &profile.name);
                    info!(
                        instance = %instance,
                        area = %area.area_id,
                        profile = %profile.name,
                        interfaces = ?interfaces,
                        "ospf profile resolved"
                    );
                }
            }
        }
        None => {
            // The watchdog would be tearing this process down anyway if the
            // instance were genuinely removed from config.
            warn!(instance = %instance, "own ospf instance missing from running config");
        }
    }
}

/// Every L3 attach point (loopback interface name, `<interface>.<tag>`
/// subinterface, or `broadcast-domain:<name>`) currently referencing
/// `profile` by name, across the whole running config. Purely a display
/// helper for the log line above — `cfg` already carries every interface
/// and broadcast domain from the same `fetch_config` call, so no extra IPC
/// round trip is needed to resolve it.
fn attach_points_for(cfg: &nos_proto::Config, profile: &str) -> Vec<String> {
    let mut points = Vec::new();
    for iface in &cfg.interfaces {
        if iface.ospf_profile.as_deref() == Some(profile) {
            points.push(iface.name.clone());
        }
        for sub in &iface.subinterfaces {
            if sub.ospf_profile.as_deref() == Some(profile) {
                points.push(format!("{}.{}", iface.name, sub.tag));
            }
        }
    }
    for domain in &cfg.broadcast_domains {
        if domain.ospf_profile.as_deref() == Some(profile) {
            points.push(format!("broadcast-domain:{}", domain.name));
        }
    }
    points
}

/// Local copy of `nos-watchdog::supervisor::wait_or_shutdown` — not
/// imported, per the star-dependency rule.
async fn wait_or_shutdown(delay: Duration, shutdown: &mut watch::Receiver<bool>) -> bool {
    tokio::select! {
        () = tokio::time::sleep(delay) => false,
        _ = shutdown.changed() => *shutdown.borrow(),
    }
}

#[cfg(test)]
mod tests {
    use nos_proto::{BroadcastDomain, Config, Interface, Subinterface};

    use super::attach_points_for;

    fn interface(name: &str, ospf_profile: Option<&str>) -> Interface {
        Interface {
            name: name.to_string(),
            addresses: Vec::new(),
            routing_table: None,
            ospf_profile: ospf_profile.map(str::to_string),
            switching_profile: None,
            subinterfaces: Vec::new(),
        }
    }

    #[test]
    fn finds_loopback_interface_attachment() {
        let cfg = Config {
            interfaces: vec![interface("loopback-rt1", Some("p1"))],
            ..Default::default()
        };
        assert_eq!(attach_points_for(&cfg, "p1"), vec!["loopback-rt1"]);
    }

    #[test]
    fn finds_subinterface_attachment() {
        let mut iface = interface("eth0", None);
        iface.subinterfaces = vec![Subinterface {
            tag: 100,
            addresses: Vec::new(),
            routing_table: None,
            ospf_profile: Some("p1".to_string()),
        }];
        let cfg = Config {
            interfaces: vec![iface],
            ..Default::default()
        };
        assert_eq!(attach_points_for(&cfg, "p1"), vec!["eth0.100"]);
    }

    #[test]
    fn finds_broadcast_domain_attachment() {
        let cfg = Config {
            broadcast_domains: vec![BroadcastDomain {
                name: "bd1".to_string(),
                addresses: Vec::new(),
                routing_table: None,
                ospf_profile: Some("p1".to_string()),
            }],
            ..Default::default()
        };
        assert_eq!(attach_points_for(&cfg, "p1"), vec!["broadcast-domain:bd1"]);
    }

    #[test]
    fn ignores_attachments_to_other_profiles() {
        let cfg = Config {
            interfaces: vec![interface("loopback-rt1", Some("other"))],
            ..Default::default()
        };
        assert!(attach_points_for(&cfg, "p1").is_empty());
    }
}
