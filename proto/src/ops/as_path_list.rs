use serde::{Deserialize, Serialize};

use crate::schema::{AsPathList, Config};

use super::OpError;

/// An edit to a single named `AsPathList` within a transaction's
/// in-progress config. Applied without validation — `garde` validation only
/// runs at commit time, matching every other `Op`. `patterns` has no
/// `Ensure`/`SetX` split since it's a plain list of scalars (not a keyed
/// collection) — `AddPattern`/`RemovePattern` mutate it directly, mirroring
/// `InterfaceOp::AddAddress`/`RemoveAddress`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum AsPathListOp {
    /// Creates the list with no patterns if it doesn't already exist by
    /// name; no-op if it does. Backs `edit as-path-list <name>`'s
    /// "create if missing, else navigate to it" semantics.
    Ensure {
        /// Name of the AS-path list this op targets.
        name: String,
    },
    /// Adds pattern `pattern` to the AS-path list.
    AddPattern {
        /// Name of the AS-path list this op targets.
        name: String,
        /// Regular expression matched against the AS path.
        pattern: String,
    },
    /// Removes pattern `pattern` from the AS-path list.
    RemovePattern {
        /// Name of the AS-path list this op targets.
        name: String,
        /// Regular expression matched against the AS path.
        pattern: String,
    },
    /// Deletes the AS-path list and everything nested under it.
    Delete {
        /// Name of the AS-path list this op targets.
        name: String,
    },
}

impl AsPathListOp {
    /// Applies this edit to `config`; fails with an `OpError` when its target is missing.
    pub fn apply(&self, config: &mut Config) -> Result<(), OpError> {
        match self {
            AsPathListOp::Ensure { name } => {
                if !config.as_path_lists.iter().any(|g| &g.name == name) {
                    config.as_path_lists.push(AsPathList {
                        name: name.clone(),
                        patterns: Vec::new(),
                    });
                }
                Ok(())
            }
            AsPathListOp::AddPattern { name, pattern } => {
                let list = find_list_mut(config, name)?;
                if !list.patterns.contains(pattern) {
                    list.patterns.push(pattern.clone());
                }
                Ok(())
            }
            AsPathListOp::RemovePattern { name, pattern } => {
                let list = find_list_mut(config, name)?;
                let before = list.patterns.len();
                list.patterns.retain(|m| m != pattern);
                if list.patterns.len() == before {
                    return Err(OpError::AsPathListPatternNotFound {
                        name: name.clone(),
                        pattern: pattern.clone(),
                    });
                }
                Ok(())
            }
            AsPathListOp::Delete { name } => {
                let before = config.as_path_lists.len();
                config.as_path_lists.retain(|g| &g.name != name);
                if config.as_path_lists.len() == before {
                    return Err(OpError::AsPathListNotFound(name.clone()));
                }
                Ok(())
            }
        }
    }
}

fn find_list_mut<'a>(config: &'a mut Config, name: &str) -> Result<&'a mut AsPathList, OpError> {
    config
        .as_path_lists
        .iter_mut()
        .find(|g| g.name == name)
        .ok_or_else(|| OpError::AsPathListNotFound(name.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn list(name: &str) -> AsPathList {
        AsPathList {
            name: name.to_string(),
            patterns: Vec::new(),
        }
    }

    #[test]
    fn ensure_creates_when_missing() {
        let mut cfg = Config::default();
        AsPathListOp::Ensure {
            name: "g1".to_string(),
        }
        .apply(&mut cfg)
        .unwrap();
        assert_eq!(cfg.as_path_lists.len(), 1);
        assert_eq!(cfg.as_path_lists[0].patterns, [] as [String; 0]);
    }

    #[test]
    fn ensure_is_idempotent_and_adds_distinct_names() {
        let mut cfg = Config::default();
        let ensure = |cfg: &mut Config, n: &str| {
            AsPathListOp::Ensure {
                name: n.to_string(),
            }
            .apply(cfg)
            .unwrap();
        };
        ensure(&mut cfg, "g1");
        AsPathListOp::AddPattern {
            name: "g1".to_string(),
            pattern: "^1$".to_string(),
        }
        .apply(&mut cfg)
        .unwrap();
        ensure(&mut cfg, "g1");
        assert_eq!(cfg.as_path_lists.len(), 1);
        assert_eq!(cfg.as_path_lists[0].patterns, ["^1$"]);
        ensure(&mut cfg, "g2");
        let names: Vec<_> = cfg.as_path_lists.iter().map(|l| l.name.as_str()).collect();
        assert_eq!(names, ["g1", "g2"]);
    }

    #[test]
    fn add_and_remove_pattern() {
        let mut cfg = Config {
            as_path_lists: vec![list("g1")],
            ..Default::default()
        };
        AsPathListOp::AddPattern {
            name: "g1".to_string(),
            pattern: "65000:100".to_string(),
        }
        .apply(&mut cfg)
        .unwrap();
        assert_eq!(cfg.as_path_lists[0].patterns, vec!["65000:100"]);

        AsPathListOp::RemovePattern {
            name: "g1".to_string(),
            pattern: "65000:100".to_string(),
        }
        .apply(&mut cfg)
        .unwrap();
        assert_eq!(cfg.as_path_lists[0].patterns, [] as [String; 0]);
    }

    #[test]
    fn add_pattern_is_idempotent() {
        let mut cfg = Config {
            as_path_lists: vec![list("g1")],
            ..Default::default()
        };
        for _ in 0..2 {
            AsPathListOp::AddPattern {
                name: "g1".to_string(),
                pattern: "65000:100".to_string(),
            }
            .apply(&mut cfg)
            .unwrap();
        }
        assert_eq!(cfg.as_path_lists[0].patterns.len(), 1);
    }

    #[test]
    fn remove_missing_pattern_errors() {
        let mut cfg = Config {
            as_path_lists: vec![list("g1")],
            ..Default::default()
        };
        let err = AsPathListOp::RemovePattern {
            name: "g1".to_string(),
            pattern: "65000:100".to_string(),
        }
        .apply(&mut cfg)
        .unwrap_err();
        assert!(matches!(
            err,
            OpError::AsPathListPatternNotFound { name, pattern }
            if name == "g1" && pattern == "65000:100"
        ));
    }

    #[test]
    fn delete_removes_existing() {
        let mut cfg = Config {
            as_path_lists: vec![list("g1"), list("g2")],
            ..Default::default()
        };
        AsPathListOp::Delete {
            name: "g1".to_string(),
        }
        .apply(&mut cfg)
        .unwrap();
        assert_eq!(cfg.as_path_lists.len(), 1);
        assert_eq!(cfg.as_path_lists[0].name, "g2");
    }

    #[test]
    fn delete_missing_list_errors() {
        let mut cfg = Config::default();
        let err = AsPathListOp::Delete {
            name: "g1".to_string(),
        }
        .apply(&mut cfg)
        .unwrap_err();
        assert!(matches!(err, OpError::AsPathListNotFound(n) if n == "g1"));
    }
}
