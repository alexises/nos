use std::io::Write as _;
use std::path::Path;

use nos_proto::Config;
use tracing::{error, info, warn};

use crate::error::ConfigError;

/// Serializes `config` as YAML and atomically writes it to `path`.
///
/// The config is first written to a temp file in the same directory as
/// `path` (guaranteeing the same filesystem, so the final rename is atomic
/// and each concurrent caller gets its own temp file), then renamed over
/// `path`. A crash or process kill mid-write can never leave a truncated or
/// partially-written file at `path`.
pub fn save_to_disk(config: &Config, path: &Path) -> Result<(), ConfigError> {
    let dir = path.parent().filter(|p| !p.as_os_str().is_empty());
    let yaml = serde_yaml::to_string(config)?;

    let mut tmp = match dir {
        Some(dir) => tempfile::NamedTempFile::new_in(dir),
        None => tempfile::NamedTempFile::new(),
    }
    .map_err(|source| persistence_error(path, source))?;
    tmp.write_all(yaml.as_bytes())
        .map_err(|source| persistence_error(path, source))?;
    tmp.persist(path)
        .map_err(|e| persistence_error(path, e.error))?;
    Ok(())
}

/// Loads a config from `path`.
///
/// A missing file is treated as a first run and yields `Config::default()`.
/// A file that exists but fails to parse is a hard error — a corrupt config
/// file must never be silently discarded in favor of a default, since that
/// risks masking real data loss.
pub fn load_or_default(path: &Path) -> Result<Config, ConfigError> {
    match std::fs::read(path) {
        Ok(bytes) => match serde_yaml::from_slice(&bytes) {
            Ok(cfg) => {
                info!(path = %path.display(), "loaded config from disk");
                Ok(cfg)
            }
            Err(e) => {
                error!(path = %path.display(), error = %e, "failed to parse config file");
                Err(e.into())
            }
        },
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            warn!(path = %path.display(), "no config file found, starting with default (empty) config");
            Ok(Config::default())
        }
        Err(source) => Err(persistence_error(path, source)),
    }
}

fn persistence_error(path: &Path, source: std::io::Error) -> ConfigError {
    ConfigError::Persistence {
        path: path.to_path_buf(),
        source,
    }
}

#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;

    use nos_proto::BgpInstance;

    use super::*;

    fn sample_config() -> Config {
        Config {
            bgp_instances: vec![BgpInstance {
                name: "default".to_string(),
                router_id: Ipv4Addr::new(10, 0, 0, 1),
                asn: 65000,
                peer_groups: Vec::new(),
                peers: Vec::new(),
                cluster_id: None,
                confederation: nos_proto::BgpConfederation::default(),
                routing_table: None,
                redistribute_policy: None,
            }],
            ..Default::default()
        }
    }

    #[test]
    fn load_or_default_returns_default_when_file_missing() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("does-not-exist.yaml");

        let cfg = load_or_default(&path).unwrap();
        assert_eq!(cfg, Config::default());
    }

    #[test]
    fn load_or_default_returns_error_on_corrupt_file() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("config.yaml");
        std::fs::write(&path, b"not: [valid: yaml: at: all").unwrap();

        let err = load_or_default(&path).unwrap_err();
        assert!(matches!(err, ConfigError::Serialization(_)));
    }

    #[test]
    fn save_then_load_round_trips() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("config.yaml");
        let cfg = sample_config();

        save_to_disk(&cfg, &path).unwrap();
        let loaded = load_or_default(&path).unwrap();
        assert_eq!(loaded, cfg);
    }

    #[test]
    fn save_overwrites_existing_file() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("config.yaml");

        save_to_disk(&Config::default(), &path).unwrap();
        save_to_disk(&sample_config(), &path).unwrap();

        let loaded = load_or_default(&path).unwrap();
        assert_eq!(loaded, sample_config());
    }

    #[test]
    fn save_leaves_no_stray_temp_file_on_success() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("config.yaml");

        save_to_disk(&sample_config(), &path).unwrap();

        let entries: Vec<_> = std::fs::read_dir(tmp.path())
            .unwrap()
            .map(|e| e.unwrap().file_name())
            .collect();
        assert_eq!(entries, vec![std::ffi::OsString::from("config.yaml")]);
    }
}
