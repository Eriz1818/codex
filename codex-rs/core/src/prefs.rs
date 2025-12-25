//! Persistent user preferences stored under `$CODEX_HOME`.

use anyhow::Context;
use serde::Deserialize;
use serde::Serialize;
use std::path::Path;
use std::path::PathBuf;
use tempfile::NamedTempFile;
use tokio::task;

const PREFS_FILE: &str = "state.toml";

#[derive(Debug, Clone, Default, Deserialize, Serialize, PartialEq, Eq)]
pub struct UserPrefs {
    #[serde(default)]
    pub auto_compact_enabled: bool,
}

pub fn prefs_path(codex_home: &Path) -> PathBuf {
    codex_home.join(PREFS_FILE)
}

pub fn load_blocking(codex_home: &Path) -> UserPrefs {
    let path = prefs_path(codex_home);
    let Ok(contents) = std::fs::read_to_string(&path) else {
        return UserPrefs::default();
    };

    match toml::from_str::<UserPrefs>(&contents) {
        Ok(prefs) => prefs,
        Err(err) => {
            tracing::warn!("failed to parse preferences at {}: {err:#}", path.display());
            UserPrefs::default()
        }
    }
}

pub async fn load(codex_home: &Path) -> UserPrefs {
    let codex_home = codex_home.to_path_buf();
    task::spawn_blocking(move || load_blocking(&codex_home))
        .await
        .unwrap_or_default()
}

pub fn store_blocking(codex_home: &Path, prefs: &UserPrefs) -> anyhow::Result<()> {
    std::fs::create_dir_all(codex_home).with_context(|| {
        format!(
            "failed to create Codex home directory at {}",
            codex_home.display()
        )
    })?;

    let tmp = NamedTempFile::new_in(codex_home)?;
    let serialized = toml::to_string_pretty(prefs).context("failed to serialize preferences")?;
    std::fs::write(tmp.path(), serialized).with_context(|| {
        format!(
            "failed to write temporary preferences file at {}",
            tmp.path().display()
        )
    })?;

    tmp.persist(prefs_path(codex_home))?;
    Ok(())
}

pub async fn set_auto_compact_enabled(codex_home: &Path, enabled: bool) -> anyhow::Result<()> {
    let codex_home = codex_home.to_path_buf();
    task::spawn_blocking(move || {
        let mut prefs = load_blocking(&codex_home);
        prefs.auto_compact_enabled = enabled;
        store_blocking(&codex_home, &prefs)
    })
    .await
    .context("preferences persistence task panicked")?
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn load_defaults_when_missing() {
        let dir = tempdir().expect("create tempdir");
        assert_eq!(load_blocking(dir.path()), UserPrefs::default());
    }

    #[test]
    fn store_and_load_roundtrip() -> anyhow::Result<()> {
        let dir = tempdir()?;
        let prefs = UserPrefs {
            auto_compact_enabled: true,
        };

        store_blocking(dir.path(), &prefs)?;
        assert_eq!(load_blocking(dir.path()), prefs);

        Ok(())
    }
}
