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
        if let Some(path) = &self.path
            && let Err(e) = write_count(path, next)
        {
            warn!(error = %e, "cannot persist ospf boot count");
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

/// RFC 3623 graceful-restart marker (`<instance>.gr`): the grace deadline in
/// unix seconds, written before the Grace-LSAs go out so the respawned
/// process skips RFC 6987's on-startup period while its helpers keep the old
/// topology. Atomic, like the boot count.
pub fn write_grace_marker(path: &Path, deadline: u64) -> io::Result<()> {
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir)?;
    }
    let tmp = path.with_extension("tmp");
    std::fs::write(&tmp, deadline.to_string())?;
    std::fs::rename(&tmp, path)
}

/// Consumes the marker (deleted whatever its content): `true` only if its
/// deadline is still ahead of `now` and at most a `u16` grace period away
/// (rejects a clock jump or garbage). Missing, unreadable or corrupt: `false`.
pub fn take_grace_marker(path: &Path, now: u64) -> bool {
    let content = match std::fs::read_to_string(path) {
        Ok(c) => c,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return false,
        Err(e) => {
            warn!(error = %e, "cannot read ospf graceful restart marker");
            String::new()
        }
    };
    if let Err(e) = std::fs::remove_file(path) {
        warn!(error = %e, "cannot delete ospf graceful restart marker");
    }
    if let Ok(deadline) = content.trim().parse::<u64>() {
        now < deadline && deadline <= now + u64::from(u16::MAX)
    } else {
        warn!("corrupt ospf graceful restart marker, ignoring");
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn grace_marker_is_consumed_once_and_checked() {
        // nosemgrep: rust.lang.security.temp-dir.temp-dir -- test scratch dir, not a security boundary.
        let dir = std::env::temp_dir().join(format!("nos-gr-{}", std::process::id()));
        let path = dir.join("i.gr");
        let _ = std::fs::remove_dir_all(&dir);
        assert!(!take_grace_marker(&path, 1000));
        write_grace_marker(&path, 1120).unwrap();
        assert!(take_grace_marker(&path, 1000));
        assert!(!path.exists());
        assert!(!take_grace_marker(&path, 1000));
        // At or past the deadline.
        write_grace_marker(&path, 1000).unwrap();
        assert!(!take_grace_marker(&path, 1000));
        // Further ahead than any u16 grace period.
        write_grace_marker(&path, 1000 + 65_536).unwrap();
        assert!(!take_grace_marker(&path, 1000));
        std::fs::write(&path, "garbage").unwrap();
        assert!(!take_grace_marker(&path, 1000));
        assert!(!path.exists());
        let _ = std::fs::remove_dir_all(&dir);
    }

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
