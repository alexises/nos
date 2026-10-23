//! Holds the kernel to the [`Plan`]: per (device, direction), the compiled
//! ACL in the live chain. Driver calls block, so each pass runs on
//! `spawn_blocking` with the engine moved in and back out.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

use tokio::sync::watch;
use tracing::{error, info, warn};

use crate::compile::Compiled;
use crate::driver::{idle, Direction, Driver};
use crate::link_client::LinkTable;
use crate::plan::{Device, Plan};

type Key = (String, Direction);

/// What one (device, direction) holds.
#[derive(Debug, Clone)]
struct Installed {
    ifindex: u32,
    chain: u32,
    /// `None`: found live at start (a previous run's), contents unknown.
    acl: Option<Arc<Compiled>>,
}

pub struct Engine<D> {
    driver: D,
    installed: BTreeMap<Key, Installed>,
    /// Attachments whose device is absent, logged once until it appears.
    pending: BTreeSet<Key>,
    /// The first known link table was checked for a previous run's entries.
    swept: bool,
}

/// The kernel name of `device`; while its bond is unknown, `Err` with a
/// name to log (`<aggregate>` or `<aggregate>.<tag>`).
fn resolve(device: &Device, links: &LinkTable) -> Result<String, String> {
    let with_tag = |base: &str, tag: u16| {
        if tag == 0 {
            base.to_string()
        } else {
            format!("{base}.{tag}")
        }
    };
    match device {
        Device::Kernel(n) => Ok(n.clone()),
        Device::Aggregate { name, tag } => match links.bond(name) {
            Some(bond) => Ok(with_tag(bond, *tag)),
            None => Err(with_tag(name, *tag)),
        },
    }
}

impl<D: Driver> Engine<D> {
    pub fn new(driver: D) -> Self {
        Self {
            driver,
            installed: BTreeMap::new(),
            pending: BTreeSet::new(),
            swept: false,
        }
    }

    pub fn driver(&self) -> &D {
        &self.driver
    }

    pub fn driver_mut(&mut self) -> &mut D {
        &mut self.driver
    }

    /// Adopts what a previous run left enforcing (D9: a crash fails
    /// closed), so the diff below replaces or detaches it.
    fn sweep(&mut self, links: &LinkTable) {
        for l in links.links.values() {
            for dir in Direction::BOTH {
                match self.driver.live_chain(l.ifindex, dir) {
                    Ok(Some(chain)) => {
                        let at = Installed {
                            ifindex: l.ifindex,
                            chain,
                            acl: None,
                        };
                        self.installed.insert((l.name.clone(), dir), at);
                    }
                    Ok(None) => {}
                    Err(e) => {
                        warn!(interface = %l.name, direction = %dir, error = %e, "could not read the acl entry");
                    }
                }
            }
        }
        self.swept = true;
    }

    /// One pass. Nothing happens until the link table is known.
    pub fn sync(&mut self, plan: &Plan, links: &LinkTable) {
        if !links.known {
            return;
        }
        if !self.swept {
            self.sweep(links);
        }
        // A device that went away took its qdisc, and our filters, with it.
        self.installed.retain(|(dev, _), at| {
            links
                .links
                .get(dev)
                .is_some_and(|l| l.ifindex == at.ifindex)
        });

        let mut desired: BTreeMap<Key, (u32, &str, Option<&Arc<Compiled>>)> = BTreeMap::new();
        let mut pending = BTreeSet::new();
        for a in &plan.attachments {
            let resolved = resolve(&a.device, links);
            let Some(link) = resolved.as_ref().ok().and_then(|n| links.links.get(n)) else {
                let (Ok(shown) | Err(shown)) = resolved;
                if !self.pending.contains(&(shown.clone(), a.dir)) {
                    info!(interface = %shown, direction = %a.dir, acl = %a.acl, reason = "absent", "acl pending");
                }
                pending.insert((shown, a.dir));
                continue;
            };
            let key = (link.name.clone(), a.dir);
            desired.insert(key, (link.ifindex, &a.acl, plan.acls.get(&a.acl)));
        }
        self.pending = pending;

        let gone: Vec<Key> = self
            .installed
            .keys()
            .filter(|k| !desired.contains_key(*k))
            .cloned()
            .collect();
        for key in gone {
            self.detach(&key);
        }
        for (key, (ifindex, name, acl)) in desired {
            // No compile yet (it failed): leave the kernel as it is.
            if let Some(acl) = acl {
                self.apply(&key, ifindex, name, acl);
            }
        }
    }

    fn apply(&mut self, key: &Key, ifindex: u32, name: &str, acl: &Arc<Compiled>) {
        let current = self.installed.get(key);
        if current
            .and_then(|c| c.acl.as_ref())
            .is_some_and(|c| c == acl)
        {
            return;
        }
        let (dev, dir) = (&key.0, key.1);
        let old = current.map(|c| c.chain);
        let chain = idle(old);
        let result = self
            .driver
            .install(ifindex, dir, chain, acl)
            .and_then(|()| self.driver.switch(ifindex, dir, chain));
        if let Err(e) = result {
            // Fail closed: the old chain stays live; drop the half-filled one.
            error!(interface = %dev, direction = %dir, acl = %name, error = %e, "acl not applied, keeping the previous state");
            let _ = self.driver.flush(ifindex, dir, chain);
            return;
        }
        if let Some(old) = old
            && let Err(e) = self.driver.flush(ifindex, dir, old)
        {
            warn!(interface = %dev, direction = %dir, chain = old, error = %e, "could not flush the old acl chain");
        }
        let at = Installed {
            ifindex,
            chain,
            acl: Some(acl.clone()),
        };
        self.installed.insert(key.clone(), at);
        info!(interface = %dev, direction = %dir, acl = %name, chain, "acl attached");
    }

    fn detach(&mut self, key: &Key) {
        let Some(at) = self.installed.remove(key) else {
            return;
        };
        match self.driver.detach(at.ifindex, key.1) {
            Ok(()) => info!(interface = %key.0, direction = %key.1, "acl detached"),
            Err(e) => {
                error!(interface = %key.0, direction = %key.1, error = %e, "acl not detached");
            }
        }
    }

    /// Clean stop (SIGINT): every entry, then its chains.
    pub fn shutdown(&mut self) {
        let keys: Vec<Key> = self.installed.keys().cloned().collect();
        for key in keys {
            self.detach(&key);
        }
    }

    /// The chains every (device, direction) points at, for tests and logs.
    pub fn live(&self) -> BTreeMap<Key, u32> {
        self.installed
            .iter()
            .map(|(k, v)| (k.clone(), v.chain))
            .collect()
    }
}

/// Runs passes on every plan or link change until `shutdown`, then removes
/// everything it installed; returns the engine (for tests).
pub async fn run<D: Driver>(
    mut engine: Engine<D>,
    mut plan_rx: watch::Receiver<Option<Plan>>,
    mut links_rx: watch::Receiver<LinkTable>,
    mut shutdown: watch::Receiver<bool>,
) -> Engine<D> {
    loop {
        let plan = plan_rx.borrow_and_update().clone();
        let links = links_rx.borrow_and_update().clone();
        if let Some(plan) = plan {
            engine = tokio::task::spawn_blocking(move || {
                engine.sync(&plan, &links);
                engine
            })
            .await
            .expect("acl pass panicked");
        }
        tokio::select! {
            r = plan_rx.changed() => if r.is_err() { break },
            r = links_rx.changed() => if r.is_err() { break },
            _ = shutdown.changed() => break,
        }
    }
    let engine = tokio::task::spawn_blocking(move || {
        engine.shutdown();
        engine
    })
    .await
    .expect("acl shutdown panicked");
    info!("acl engine stopped");
    engine
}

#[cfg(test)]
#[path = "engine_tests.rs"]
mod tests;
