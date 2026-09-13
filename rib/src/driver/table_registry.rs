use std::collections::HashMap;
use std::io::{self, Write as _};
use std::path::Path;

use fs2::FileExt as _;
use serde::{Deserialize, Serialize};

/// Linux reserves 0 (unspec), 253 (default), 254 (main), 255 (local).
pub const MIN_TABLE_ID: u32 = 100;
pub const MAX_TABLE_ID: u32 = 252;

#[derive(Debug, Default, Serialize, Deserialize)]
struct Registry {
    #[serde(default)]
    by_name: HashMap<String, u32>,
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
    if let Some(dir) = path.parent().filter(|p| !p.as_os_str().is_empty()) {
        std::fs::create_dir_all(dir)?;
    }
    let lock_file = std::fs::OpenOptions::new()
        .create(true)
        .truncate(false)
        .write(true)
        .open(lock_path(path))?;
    lock_file.lock_exclusive()?;
    let result = (|| {
        let mut reg = load(path)?;
        if let Some(&id) = reg.by_name.get(table_name) {
            return Ok(id);
        }
        let used: std::collections::HashSet<u32> = reg.by_name.values().copied().collect();
        let id = (MIN_TABLE_ID..=MAX_TABLE_ID)
            .find(|id| !used.contains(id))
            .ok_or_else(|| {
                io::Error::other(format!(
                    "table id range ({MIN_TABLE_ID}..={MAX_TABLE_ID}) exhausted"
                ))
            })?;
        reg.by_name.insert(table_name.to_string(), id);
        save(path, &reg)?;
        Ok(id)
    })();
    let _ = fs2::FileExt::unlock(&lock_file);
    result
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
        Ok(bytes) => Ok(serde_yaml::from_slice(&bytes).unwrap_or_default()),
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(Registry::default()),
        Err(e) => Err(e),
    }
}

/// Same atomic-write pattern as `config::persistence::save_to_disk`: a temp
/// file in the same directory (guaranteeing the same filesystem, so the
/// final rename is atomic), then renamed over `path`.
fn save(path: &Path, reg: &Registry) -> io::Result<()> {
    let dir = path.parent().filter(|p| !p.as_os_str().is_empty());
    let yaml = serde_yaml::to_string(reg).expect("Registry serialization cannot fail");

    let mut tmp = match dir {
        Some(dir) => tempfile::NamedTempFile::new_in(dir),
        None => tempfile::NamedTempFile::new(),
    }?;
    tmp.write_all(yaml.as_bytes())?;
    tmp.persist(path).map_err(|e| e.error)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;
    use std::thread;

    use super::*;

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
