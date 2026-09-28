//! RFC 7474's persisted boot count — the high 32 bits of an extended
//! cryptographic sequence number. Every (re)start of a link driver takes a
//! fresh, strictly larger value, so a neighbor's replay check never sees the
//! sequence go backwards across a link restart *or* a process restart.

use std::io;
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

use tracing::warn;

pub struct BootCounter {
    /// `None` keeps the count in memory only (tests).
    path: Option<PathBuf>,
    last: Mutex<u32>,
}

impl BootCounter {
    pub fn in_memory() -> Self {
        Self {
            path: None,
            last: Mutex::new(0),
        }
    }

    /// Persists to `path` (parent directory created if missing).
    pub fn persistent(path: PathBuf) -> Self {
        Self {
            path: Some(path),
            last: Mutex::new(0),
        }
    }

    /// Returns the next boot count, durably recorded before it is returned.
    pub fn next(&self) -> u32 {
        let mut last = self
            .last
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let stored = self.path.as_deref().map_or(Ok(0), read_count);
        let next = match stored {
            Ok(n) => n.max(*last).saturating_add(1),
            Err(e) => {
                // ponytail: an unreadable/corrupt file falls back to wall-clock
                // seconds — far above any real boot count, so still increasing
                // here; a later good file with a smaller value would regress.
                warn!(error = %e, "cannot read ospf boot count, using the clock");
                let now = SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .map_or(0, |d| u32::try_from(d.as_secs()).unwrap_or(u32::MAX));
                now.max(*last).saturating_add(1)
            }
        };
        if let Some(path) = &self.path {
            if let Err(e) = write_count(path, next) {
                warn!(error = %e, "cannot persist ospf boot count");
            }
        }
        *last = next;
        next
    }
}

fn read_count(path: &Path) -> io::Result<u32> {
    match std::fs::read_to_string(path) {
        Ok(s) => s
            .trim()
            .parse()
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e)),
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(0),
        Err(e) => Err(e),
    }
}

fn write_count(path: &Path, n: u32) -> io::Result<()> {
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir)?;
    }
    let tmp = path.with_extension("tmp");
    std::fs::write(&tmp, n.to_string())?;
    std::fs::rename(&tmp, path)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn increments_and_survives_restart() {
        // nosemgrep: rust.lang.security.temp-dir.temp-dir -- test scratch dir, not a security boundary.
        let dir = std::env::temp_dir().join(format!("nos-boot-{}", std::process::id()));
        let path = dir.join("i.boot");
        let _ = std::fs::remove_dir_all(&dir);
        let c = BootCounter::persistent(path.clone());
        assert_eq!((c.next(), c.next()), (1, 2));
        // A new process (fresh counter object) continues from the file.
        assert_eq!(BootCounter::persistent(path.clone()).next(), 3);
        // A corrupt file must not reset to a low value.
        std::fs::write(&path, "garbage").unwrap();
        assert!(BootCounter::persistent(path).next() > 1_000_000);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn in_memory_is_strictly_increasing() {
        let c = BootCounter::in_memory();
        assert!(c.next() < c.next());
    }
}
