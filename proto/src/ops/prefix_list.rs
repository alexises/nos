use serde::{Deserialize, Serialize};

use crate::schema::{Config, PrefixList, PrefixListEntry};

use super::OpError;

/// An edit to a single named `PrefixList` within a transaction's in-progress
/// config. Applied without validation — `garde` validation only runs at
/// commit time, matching every other `Op`. `entries` has no `Ensure`/`SetX`
/// split since it's a plain list of scalars (not a keyed collection) —
/// `AddEntry`/`RemoveEntry` mutate it directly, mirroring
/// `InterfaceOp::AddAddress`/`RemoveAddress`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum PrefixListOp {
    /// Creates the prefix-list with no entries if it doesn't already exist
    /// by name; no-op if it does. Backs `edit prefix-list <name>`'s "create
    /// if missing, else navigate to it" semantics.
    Ensure {
        name: String,
    },
    AddEntry {
        name: String,
        entry: PrefixListEntry,
    },
    RemoveEntry {
        name: String,
        entry: PrefixListEntry,
    },
    Delete {
        name: String,
    },
}

impl PrefixListOp {
    pub fn apply(&self, config: &mut Config) -> Result<(), OpError> {
        match self {
            PrefixListOp::Ensure { name } => {
                if !config.prefix_lists.iter().any(|p| &p.name == name) {
                    config.prefix_lists.push(PrefixList {
                        name: name.clone(),
                        entries: Vec::new(),
                    });
                }
                Ok(())
            }
            PrefixListOp::AddEntry { name, entry } => {
                let list = find_list_mut(config, name)?;
                if !list.entries.contains(entry) {
                    list.entries.push(*entry);
                }
                Ok(())
            }
            PrefixListOp::RemoveEntry { name, entry } => {
                let list = find_list_mut(config, name)?;
                let before = list.entries.len();
                list.entries.retain(|e| e != entry);
                if list.entries.len() == before {
                    return Err(OpError::PrefixListEntryNotFound {
                        name: name.clone(),
                        entry: *entry,
                    });
                }
                Ok(())
            }
            PrefixListOp::Delete { name } => {
                let before = config.prefix_lists.len();
                config.prefix_lists.retain(|p| &p.name != name);
                if config.prefix_lists.len() == before {
                    return Err(OpError::PrefixListNotFound(name.clone()));
                }
                Ok(())
            }
        }
    }
}

fn find_list_mut<'a>(config: &'a mut Config, name: &str) -> Result<&'a mut PrefixList, OpError> {
    config
        .prefix_lists
        .iter_mut()
        .find(|p| p.name == name)
        .ok_or_else(|| OpError::PrefixListNotFound(name.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn list(name: &str) -> PrefixList {
        PrefixList {
            name: name.to_string(),
            entries: Vec::new(),
        }
    }

    fn entry(cidr: &str) -> PrefixListEntry {
        PrefixListEntry {
            cidr: cidr.parse().unwrap(),
            range: None,
        }
    }

    #[test]
    fn ensure_creates_when_missing() {
        let mut cfg = Config::default();
        PrefixListOp::Ensure {
            name: "l1".to_string(),
        }
        .apply(&mut cfg)
        .unwrap();
        assert_eq!(cfg.prefix_lists.len(), 1);
        assert_eq!(cfg.prefix_lists[0].entries, []);
    }

    #[test]
    fn add_and_remove_entry() {
        let mut cfg = Config {
            prefix_lists: vec![list("l1")],
            ..Default::default()
        };
        PrefixListOp::AddEntry {
            name: "l1".to_string(),
            entry: entry("10.0.0.0/8"),
        }
        .apply(&mut cfg)
        .unwrap();
        assert_eq!(cfg.prefix_lists[0].entries, vec![entry("10.0.0.0/8")]);

        PrefixListOp::RemoveEntry {
            name: "l1".to_string(),
            entry: entry("10.0.0.0/8"),
        }
        .apply(&mut cfg)
        .unwrap();
        assert_eq!(cfg.prefix_lists[0].entries, []);
    }

    #[test]
    fn add_entry_is_idempotent() {
        let mut cfg = Config {
            prefix_lists: vec![list("l1")],
            ..Default::default()
        };
        for _ in 0..2 {
            PrefixListOp::AddEntry {
                name: "l1".to_string(),
                entry: entry("10.0.0.0/8"),
            }
            .apply(&mut cfg)
            .unwrap();
        }
        assert_eq!(cfg.prefix_lists[0].entries.len(), 1);
    }

    #[test]
    fn remove_missing_entry_errors() {
        let mut cfg = Config {
            prefix_lists: vec![list("l1")],
            ..Default::default()
        };
        let err = PrefixListOp::RemoveEntry {
            name: "l1".to_string(),
            entry: entry("10.0.0.0/8"),
        }
        .apply(&mut cfg)
        .unwrap_err();
        assert!(matches!(
            err,
            OpError::PrefixListEntryNotFound { name, entry }
            if name == "l1" && entry == self::entry("10.0.0.0/8")
        ));
    }

    #[test]
    fn delete_removes_existing() {
        let mut cfg = Config {
            prefix_lists: vec![list("l1"), list("l2")],
            ..Default::default()
        };
        PrefixListOp::Delete {
            name: "l1".to_string(),
        }
        .apply(&mut cfg)
        .unwrap();
        assert_eq!(cfg.prefix_lists.len(), 1);
        assert_eq!(cfg.prefix_lists[0].name, "l2");
    }

    #[test]
    fn delete_missing_list_errors() {
        let mut cfg = Config::default();
        let err = PrefixListOp::Delete {
            name: "l1".to_string(),
        }
        .apply(&mut cfg)
        .unwrap_err();
        assert!(matches!(err, OpError::PrefixListNotFound(n) if n == "l1"));
    }
}
