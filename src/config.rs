//! Configuration persistée — `%APPDATA%/ats-opsec/config.toml` (Windows) ou
//! `~/.config/ats-opsec/config.toml`. En v0.3 : version scellée par mot de
//! passe maître (voir SPEC §2.2).

use crate::crypto::Argon2Params;
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Mode {
    Standard,
    Expert,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct Config {
    pub mode: Mode,
    pub theme: String,
    pub boot_anim: bool,
    pub argon2: Argon2Params,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            mode: Mode::Standard,
            theme: "cyber".into(),
            boot_anim: true,
            argon2: Argon2Params::default(),
        }
    }
}

impl Config {
    pub fn path() -> Option<PathBuf> {
        Some(dirs::config_dir()?.join("ats-opsec").join("config.toml"))
    }

    pub fn load() -> Self {
        Self::path()
            .and_then(|p| std::fs::read_to_string(p).ok())
            .and_then(|s| toml::from_str(&s).ok())
            .unwrap_or_default()
    }

    pub fn save(&self) -> std::io::Result<PathBuf> {
        let path = Self::path().ok_or_else(|| {
            std::io::Error::new(std::io::ErrorKind::NotFound, "config dir introuvable")
        })?;
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let body = toml::to_string_pretty(self)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
        std::fs::write(&path, body)?;
        Ok(path)
    }
}
