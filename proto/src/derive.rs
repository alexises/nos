use crate::schema::Config;

/// Recomputes every `BgpInstance.routing_table` from the authoritative
/// `RoutingTable.bgp_instance` references. Pure and synchronous, like
/// `ops::apply`/`diff::diff_*` — call this on any `Config` that is about to
/// become "running" (see `nos-config`'s `ConfigStore::new` and
/// `commit_transaction`), never on a transaction's in-progress config.
///
/// `RoutingTable.bgp_instance`'s own `garde` validation already guarantees
/// at most one table claims a given instance at commit time, so this never
/// has to arbitrate a conflict — it just clears every instance's mirror and
/// re-populates it from whichever single claim exists, if any.
pub fn sync_routing_table_refs(config: &mut Config) {
    for instance in &mut config.bgp_instances {
        instance.routing_table = None;
    }
    for table in &config.routing_tables {
        let Some(bgp_instance) = &table.bgp_instance else {
            continue;
        };
        if let Some(instance) = config
            .bgp_instances
            .iter_mut()
            .find(|i| &i.name == bgp_instance)
        {
            instance.routing_table = Some(table.name.clone());
        }
    }
}

#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;

    use super::*;
    use crate::schema::{BgpInstance, RoutingTable};

    fn instance(name: &str) -> BgpInstance {
        BgpInstance {
            name: name.to_string(),
            router_id: Ipv4Addr::new(1, 1, 1, 1),
            asn: 65000,
            peer_groups: Vec::new(),
            peers: Vec::new(),
            routing_table: None,
        }
    }

    fn table(name: &str, bgp_instance: Option<&str>) -> RoutingTable {
        RoutingTable {
            name: name.to_string(),
            bgp_instance: bgp_instance.map(str::to_string),
            static_routing_instance: None,
        }
    }

    #[test]
    fn claimed_instance_gets_mirrored_reference() {
        let mut cfg = Config {
            bgp_instances: vec![instance("r1")],
            routing_tables: vec![table("rt1", Some("r1"))],
            ..Default::default()
        };
        sync_routing_table_refs(&mut cfg);
        assert_eq!(cfg.bgp_instances[0].routing_table.as_deref(), Some("rt1"));
    }

    #[test]
    fn unclaimed_instance_stays_none() {
        let mut cfg = Config {
            bgp_instances: vec![instance("r1")],
            routing_tables: vec![table("rt1", None)],
            ..Default::default()
        };
        sync_routing_table_refs(&mut cfg);
        assert_eq!(cfg.bgp_instances[0].routing_table, None);
    }

    #[test]
    fn stale_reference_is_cleared_when_claim_is_removed() {
        let mut cfg = Config {
            bgp_instances: vec![BgpInstance {
                routing_table: Some("stale".to_string()),
                ..instance("r1")
            }],
            routing_tables: vec![table("rt1", None)],
            ..Default::default()
        };
        sync_routing_table_refs(&mut cfg);
        assert_eq!(cfg.bgp_instances[0].routing_table, None);
    }

    #[test]
    fn reassigned_claim_updates_the_mirror() {
        let mut cfg = Config {
            bgp_instances: vec![instance("r1")],
            routing_tables: vec![table("rt1", None), table("rt2", Some("r1"))],
            ..Default::default()
        };
        sync_routing_table_refs(&mut cfg);
        assert_eq!(cfg.bgp_instances[0].routing_table.as_deref(), Some("rt2"));
    }
}
