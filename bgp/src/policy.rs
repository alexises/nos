//! Compiled-policy cache for BGP import/export — see root `CLAUDE.md`'s
//! "Wire/cache". Only `PolicyDefinition.source` ever crosses IPC/diff; each
//! `nos-bgpd` compiles and caches its own bytecode here, rebuilt wholesale on
//! every config resync (matching the existing "always rebuild own state
//! fully from a fresh fetch" convention `reconcile.rs` already uses for
//! peers/VRF, not incremental patching).

use std::collections::HashMap;
use std::sync::Arc;

use nos_proto::schema::PolicyDefinition;
use nos_rpl::CompiledPolicy;
use tracing::error;

pub struct PolicyCache {
    compiled: HashMap<String, Arc<CompiledPolicy>>,
    accept_all: Arc<CompiledPolicy>,
    deny_all: Arc<CompiledPolicy>,
}

impl Default for PolicyCache {
    fn default() -> Self {
        PolicyCache {
            compiled: HashMap::new(),
            accept_all: Arc::new(nos_rpl::ACCEPT_ALL.clone()),
            deny_all: Arc::new(nos_rpl::DENY_ALL.clone()),
        }
    }
}

impl PolicyCache {
    /// Recompiles every named policy from a freshly-fetched config. A
    /// compile failure here should never happen — `nos-configd` already
    /// rejected bad source at commit time — so on failure the previous
    /// compiled version for that name is kept (if any) rather than falling
    /// back to `deny-all` and flapping every route over a hypothetical
    /// crate-version skew between `nos-configd` and `nos-bgpd`.
    pub fn resync(&mut self, policies: &[PolicyDefinition]) {
        let mut next = HashMap::with_capacity(policies.len());
        for policy in policies {
            match nos_rpl::compile(&policy.source) {
                Ok(compiled) => {
                    next.insert(policy.name.clone(), Arc::new(compiled));
                }
                Err(e) => {
                    error!(
                        policy = %policy.name, error = %e,
                        "policy failed to recompile; keeping previous compiled version"
                    );
                    if let Some(prev) = self.compiled.get(&policy.name) {
                        next.insert(policy.name.clone(), Arc::clone(prev));
                    }
                }
            }
        }
        self.compiled = next;
    }

    /// Resolves a peer-group's `import_policy`/`export_policy` field to its
    /// compiled form. `None` is `deny-all` — this NOS never leaves a
    /// direction unfiltered, see root `CLAUDE.md`'s "Default-deny rollout
    /// impact". `Some("accept-all")`/`Some("deny-all")` are the two built-in
    /// system policies; any other name is looked up in the cache, falling
    /// back to `deny-all` (with an error log) if it's somehow missing —
    /// shouldn't happen, since `nos-config` already validated the reference
    /// at commit time.
    pub fn resolve(&self, name: Option<&str>) -> Arc<CompiledPolicy> {
        match name {
            None => Arc::clone(&self.deny_all),
            Some(n) if n == nos_rpl::ACCEPT_ALL_NAME => Arc::clone(&self.accept_all),
            Some(n) if n == nos_rpl::DENY_ALL_NAME => Arc::clone(&self.deny_all),
            Some(n) => self.compiled.get(n).map_or_else(
                || {
                    error!(
                        policy = n,
                        "referenced policy not found in cache; treating as deny-all"
                    );
                    Arc::clone(&self.deny_all)
                },
                Arc::clone,
            ),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn policy(name: &str, source: &str) -> PolicyDefinition {
        PolicyDefinition {
            name: name.to_string(),
            source: source.to_string(),
        }
    }

    fn accepts(policy: &CompiledPolicy) -> bool {
        let input = nos_rpl::Input {
            prefix: "10.0.0.0/8".parse().unwrap(),
            bgp: nos_rpl::BgpInput {
                origin: nos_rpl::Origin::Igp,
                as_path: &[],
                local_pref: 100,
                med: None,
                next_hop: None,
                learned_via_ibgp: false,
                router_id: None,
                originator_id: None,
                cluster_list: &[],
                communities: &[],
                extended_communities: &[],
                large_communities: &[],
            },
        };
        matches!(
            nos_rpl::vm::run(policy, &input),
            nos_rpl::Verdict::Accept { .. }
        )
    }

    #[test]
    fn unset_resolves_to_deny_all() {
        let cache = PolicyCache::default();
        assert!(!accepts(&cache.resolve(None)));
    }

    #[test]
    fn accept_all_name_resolves_without_any_config() {
        let cache = PolicyCache::default();
        assert!(accepts(&cache.resolve(Some("accept-all"))));
    }

    #[test]
    fn deny_all_name_resolves_without_any_config() {
        let cache = PolicyCache::default();
        assert!(!accepts(&cache.resolve(Some("deny-all"))));
    }

    #[test]
    fn named_policy_resolves_after_resync() {
        let mut cache = PolicyCache::default();
        cache.resync(&[policy("p1", "accept\n")]);
        assert!(accepts(&cache.resolve(Some("p1"))));
    }

    #[test]
    fn unknown_name_falls_back_to_deny_all() {
        let cache = PolicyCache::default();
        assert!(!accepts(&cache.resolve(Some("does-not-exist"))));
    }

    #[test]
    fn failed_recompile_keeps_previous_version() {
        let mut cache = PolicyCache::default();
        cache.resync(&[policy("p1", "accept\n")]);
        assert!(accepts(&cache.resolve(Some("p1"))));

        // A syntactically invalid source should never actually reach here
        // (nos-config rejects it at commit), but the cache must still
        // degrade gracefully rather than losing the last-known-good policy.
        cache.resync(&[policy("p1", "if this.prefix in :\n    accept\n")]);
        assert!(accepts(&cache.resolve(Some("p1"))));
    }
}
