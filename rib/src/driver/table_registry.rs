use std::collections::HashMap;
use std::io::{self, Write as _};
use std::path::Path;

use fs2::FileExt as _;
use serde::{Deserialize, Serialize};
use tracing::{debug, error, info, trace, warn};

/// Linux reserves 0 (unspec), 253 (default), 254 (main), 255 (local).
pub const MIN_TABLE_ID: u32 = 100;
pub const MAX_TABLE_ID: u32 = 252;
/// Allocated VPN labels start here: below it are the reserved labels (0-15)
/// and room for operator-chosen static ones.
pub const LABEL_BASE: u32 = 1000;
/// The largest 20-bit MPLS label.
pub const MAX_LABEL: u32 = 1_048_575;

#[derive(Debug, Default, Serialize, Deserialize)]
struct Registry {
    #[serde(default)]
    by_name: HashMap<String, u32>,
    /// Per-VRF VPN label (#580), allocated like the table ids, never freed.
    #[serde(default, skip_serializing_if = "HashMap::is_empty")]
    labels: HashMap<String, u32>,
}

/// Returns the persisted kernel table id for `table_name`, allocating
/// (smallest unused id in `MIN_TABLE_ID..=MAX_TABLE_ID`) and persisting a
/// fresh one on first use. Reused verbatim on every later call for the same
/// name — including across a full process restart, since it's read from
/// disk, not recomputed — so a crash/restart reuses the same VRF name. This
/// is purely `nos-ribd`'s own private persistence: no other process ever
/// reads this file (see `LinuxRibDriver::vrf_name`/`RibRequest::GetVrfName`
/// for how other daemons learn the resulting name instead).
///
/// Takes an exclusive lock on a `.lock` sibling file for the whole
/// read-allocate-write sequence: multiple `nos-ribd` instances (one per
/// table) share this one file, and the first-diff-is-authoritative watchdog
/// sync (root `CLAUDE.md`) can spawn several of them at once, so without
/// locking two instances could both compute the same "smallest free id" and
/// collide.
pub fn ensure_table_id(path: &Path, table_name: &str) -> io::Result<u32> {
    locked(path, table_name, |reg| {
        if let Some(&id) = reg.by_name.get(table_name) {
            trace!(table = %table_name, table_id = id, "reusing allocated table id");
            return Ok(id);
        }
        let used: std::collections::HashSet<u32> = reg.by_name.values().copied().collect();
        let id = (MIN_TABLE_ID..=MAX_TABLE_ID)
            .find(|id| !used.contains(id))
            .ok_or_else(|| {
                error!(
                    table = %table_name,
                    min = MIN_TABLE_ID,
                    max = MAX_TABLE_ID,
                    "table id range exhausted, cannot allocate"
                );
                io::Error::other(format!(
                    "table id range ({MIN_TABLE_ID}..={MAX_TABLE_ID}) exhausted"
                ))
            })?;
        reg.by_name.insert(table_name.to_string(), id);
        save(path, reg)?;
        info!(table = %table_name, table_id = id, "allocated new kernel routing table id");
        Ok(id)
    })
}

/// Runs `f` over the loaded registry under the exclusive `.lock` (see
/// `ensure_table_id`); `f` saves what it changed.
fn locked<T>(
    path: &Path,
    table_name: &str,
    f: impl FnOnce(&mut Registry) -> io::Result<T>,
) -> io::Result<T> {
    if let Some(dir) = path.parent().filter(|p| !p.as_os_str().is_empty()) {
        std::fs::create_dir_all(dir)?;
    }
    let lock_file = std::fs::OpenOptions::new()
        .create(true)
        .truncate(false)
        .write(true)
        .open(lock_path(path))?;
    lock_file.lock_exclusive()?;
    let result = load(path).and_then(|mut reg| f(&mut reg));
    if let Err(e) = fs2::FileExt::unlock(&lock_file) {
        warn!(table = %table_name, error = %e, "failed to unlock table-id registry lock file");
    }
    result
}

/// The persisted VPN label of `table_name`, allocating the smallest label of
/// `LABEL_BASE..=MAX_LABEL` that no other table holds and that is not in
/// `reserved` (every explicit `vpn.label` of the config) on first use, under
/// the same lock and in the same file as the table ids. A persisted label
/// that has since become someone's explicit one is replaced. Never freed, so
/// re-adding `vpn` gets the same label back.
pub fn ensure_label<S: std::hash::BuildHasher>(
    path: &Path,
    table_name: &str,
    reserved: &std::collections::HashSet<u32, S>,
) -> io::Result<u32> {
    locked(path, table_name, |reg| {
        if let Some(&l) = reg.labels.get(table_name).filter(|l| !reserved.contains(l)) {
            return Ok(l);
        }
        let used: std::collections::HashSet<u32> = reg
            .labels
            .iter()
            .filter(|(t, _)| t.as_str() != table_name)
            .map(|(_, &l)| l)
            .collect();
        let label = (LABEL_BASE..=MAX_LABEL)
            .find(|l| !used.contains(l) && !reserved.contains(l))
            .ok_or_else(|| io::Error::other("vpn label range exhausted"))?;
        reg.labels.insert(table_name.to_string(), label);
        save(path, reg)?;
        info!(table = %table_name, label, "vpn label allocated");
        Ok(label)
    })
}

/// Read-only, no lock needed — atomic renames (see `save`) mean a reader
/// never observes a torn write. `None` if this table has never had
/// `ensure_table_id` succeed. Backs `teardown` and `vrf_name`.
pub fn lookup_table_id(path: &Path, table_name: &str) -> Option<u32> {
    load(path).ok()?.by_name.get(table_name).copied()
}

pub fn vrf_ifname(table_id: u32) -> String {
    format!("vrf{table_id}")
}

fn lock_path(path: &Path) -> std::path::PathBuf {
    path.with_extension("lock")
}

fn load(path: &Path) -> io::Result<Registry> {
    match std::fs::read(path) {
        Ok(bytes) => Ok(serde_norway::from_slice(&bytes).unwrap_or_else(|e| {
            warn!(
                path = %path.display(),
                error = %e,
                "failed to parse table-id registry, starting from an empty registry"
            );
            Registry::default()
        })),
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(Registry::default()),
        Err(e) => Err(e),
    }
}

/// Same atomic-write pattern as `config::persistence::save_to_disk`: a temp
/// file in the same directory (guaranteeing the same filesystem, so the
/// final rename is atomic), then renamed over `path`.
fn save(path: &Path, reg: &Registry) -> io::Result<()> {
    let dir = path.parent().filter(|p| !p.as_os_str().is_empty());
    let yaml = serde_norway::to_string(reg).expect("Registry serialization cannot fail");

    let mut tmp = match dir {
        Some(dir) => tempfile::NamedTempFile::new_in(dir),
        None => tempfile::NamedTempFile::new(),
    }?;
    tmp.write_all(yaml.as_bytes())?;
    tmp.persist(path).map_err(|e| e.error)?;
    debug!(path = %path.display(), entries = reg.by_name.len(), "persisted table-id registry");
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;
    use std::thread;

    use super::*;

    /// #415: a file written by the old `serde_yaml` 0.9 still loads under `serde_norway`.
    #[test]
    fn registry_written_by_serde_yaml_0_9_still_loads() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("table-ids.yaml");
        std::fs::write(&path, "by_name:\n  rt1: 100\n  rt2: 101\n").unwrap();
        assert_eq!(lookup_table_id(&path, "rt2"), Some(101));
        assert_eq!(ensure_table_id(&path, "rt3").unwrap(), 102);
    }

    /// #580: a registry written before labels existed still loads, and a
    /// label persists across a reload without disturbing the table ids.
    #[test]
    fn vpn_labels_are_stable_skip_explicit_ones_and_coexist_with_table_ids() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("table-ids.yaml");
        std::fs::write(&path, "by_name:\n  red: 100\n").unwrap();
        let none: std::collections::HashSet<u32> = std::collections::HashSet::new();
        assert_eq!(ensure_label(&path, "red", &none).unwrap(), LABEL_BASE);
        assert_eq!(ensure_label(&path, "red", &none).unwrap(), LABEL_BASE);
        assert_eq!(lookup_table_id(&path, "red"), Some(100));
        let reserved: std::collections::HashSet<u32> = [LABEL_BASE + 1].into_iter().collect();
        assert_eq!(
            ensure_label(&path, "blue", &reserved).unwrap(),
            LABEL_BASE + 2
        );
        // `red`'s label became another table's explicit one: reallocated.
        let taken: std::collections::HashSet<u32> = [LABEL_BASE].into_iter().collect();
        assert_eq!(ensure_label(&path, "red", &taken).unwrap(), LABEL_BASE + 1);
        assert_eq!(ensure_table_id(&path, "blue").unwrap(), 101);
        assert_eq!(ensure_label(&path, "blue", &none).unwrap(), LABEL_BASE + 2);
    }

    #[test]
    fn vpn_label_exhaustion_errors() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("table-ids.yaml");
        let all: std::collections::HashSet<u32> = (LABEL_BASE..=MAX_LABEL).collect();
        let err = ensure_label(&path, "red", &all).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::Other);
    }

    #[test]
    fn allocating_twice_for_the_same_name_reuses_the_id() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("table-ids.yaml");

        let first = ensure_table_id(&path, "rt1").unwrap();
        let second = ensure_table_id(&path, "rt1").unwrap();
        assert_eq!(first, second);
    }

    #[test]
    fn different_names_get_distinct_ids() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("table-ids.yaml");

        let a = ensure_table_id(&path, "rt1").unwrap();
        let b = ensure_table_id(&path, "rt2").unwrap();
        assert_ne!(a, b);
    }

    #[test]
    fn allocation_picks_smallest_free_id() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("table-ids.yaml");

        let a = ensure_table_id(&path, "rt1").unwrap();
        assert_eq!(a, MIN_TABLE_ID);
        let b = ensure_table_id(&path, "rt2").unwrap();
        assert_eq!(b, MIN_TABLE_ID + 1);
    }

    #[test]
    fn lookup_of_missing_entry_is_none() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("table-ids.yaml");
        assert!(lookup_table_id(&path, "rt1").is_none());

        ensure_table_id(&path, "rt1").unwrap();
        assert!(lookup_table_id(&path, "rt2").is_none());
        assert_eq!(lookup_table_id(&path, "rt1"), Some(MIN_TABLE_ID));
    }

    #[test]
    fn lookup_against_a_missing_file_is_none() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("does-not-exist.yaml");
        assert!(lookup_table_id(&path, "rt1").is_none());
    }

    #[test]
    fn range_exhaustion_errors() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("table-ids.yaml");

        for i in 0..=(MAX_TABLE_ID - MIN_TABLE_ID) {
            ensure_table_id(&path, &format!("rt{i}")).unwrap();
        }
        let err = ensure_table_id(&path, "one-too-many").unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::Other);
    }

    #[test]
    fn vrf_ifname_formats_from_id() {
        assert_eq!(vrf_ifname(100), "vrf100");
        assert_eq!(vrf_ifname(252), "vrf252");
    }

    #[test]
    fn concurrent_allocations_for_different_names_never_collide() {
        let tmp = tempfile::tempdir().unwrap();
        let path = Arc::new(tmp.path().join("table-ids.yaml"));

        let handles: Vec<_> = (0..20)
            .map(|i| {
                let path = Arc::clone(&path);
                thread::spawn(move || ensure_table_id(&path, &format!("rt{i}")).unwrap())
            })
            .collect();
        let ids: Vec<u32> = handles.into_iter().map(|h| h.join().unwrap()).collect();

        let unique: std::collections::HashSet<u32> = ids.iter().copied().collect();
        assert_eq!(
            unique.len(),
            ids.len(),
            "two threads allocated the same id: {ids:?}"
        );
    }
}
