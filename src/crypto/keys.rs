//! Trousseau local : paires X-Wing dans `%CONFIG%/ats-opsec/keys/`.
//!
//! `.pub` = JSON clair {name, type, key_hex, fingerprint, created}
//! `.sec` = JSON {… + secret_hex} — v0.2 : fichier brut (warning affiché),
//!          scellement par mot de passe maître prévu v0.3.

use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use super::kem::{self, XwingPublic, XwingSecret};
use crate::error::{OpsecError, Result};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PubKeyFile {
    pub name: String,
    #[serde(rename = "type")]
    pub kind: String, // "xwing"
    pub key_hex: String,
    pub fingerprint: String,
    pub created: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecKeyFile {
    #[serde(flatten)]
    pub public: PubKeyFile,
    pub secret_hex: String,
}

pub fn keys_dir() -> Result<PathBuf> {
    let base = dirs::config_dir()
        .ok_or_else(|| OpsecError::InvalidParam("config dir introuvable".into()))?;
    Ok(base.join("ats-opsec").join("keys"))
}

/// Génère une paire X-Wing, sauvegarde `.pub` + `.sec`, retourne les chemins
/// + fingerprint.
pub fn keygen(name: &str) -> Result<(PathBuf, PathBuf, String)> {
    validate_name(name)?;
    let dir = keys_dir()?;
    std::fs::create_dir_all(&dir)?;

    let (sec, pub_) = kem::keygen()?;
    let fp = pub_.fingerprint();
    let created = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);

    let pubf = PubKeyFile {
        name: name.to_string(),
        kind: "xwing".into(),
        key_hex: hex::encode(pub_.to_bytes()),
        fingerprint: fp.clone(),
        created,
    };
    let secf = SecKeyFile {
        public: pubf.clone(),
        secret_hex: hex::encode(sec.to_bytes().as_slice()),
    };

    let pub_path = dir.join(format!("{name}.pub"));
    let sec_path = dir.join(format!("{name}.sec"));
    std::fs::write(&pub_path, serde_json::to_string_pretty(&pubf).unwrap())?;
    std::fs::write(&sec_path, serde_json::to_string_pretty(&secf).unwrap())?;
    // Permissions restrictives sur la clé secrète (Unix).
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(&sec_path, std::fs::Permissions::from_mode(0o600));
    }
    Ok((pub_path, sec_path, fp))
}

fn validate_name(name: &str) -> Result<()> {
    if name.is_empty()
        || name.len() > 32
        || !name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.'))
    {
        return Err(OpsecError::InvalidParam(
            "nom de clé: [a-z0-9._-], 1-32 chars".into(),
        ));
    }
    Ok(())
}

/// Charge une clé publique : chemin de fichier `.pub` OU nom dans le keyring
/// (`@alice` ou `alice`).
pub fn load_public(spec: &str) -> Result<XwingPublic> {
    let path = resolve(spec, "pub")?;
    let txt = std::fs::read_to_string(&path)?;
    let f: PubKeyFile =
        serde_json::from_str(&txt).map_err(|e| OpsecError::Header(format!("pub key json: {e}")))?;
    let raw = hex::decode(&f.key_hex).map_err(|_| OpsecError::Header("pub key hex".into()))?;
    XwingPublic::from_bytes(&raw)
}

pub fn load_secret(spec: &str) -> Result<XwingSecret> {
    let path = resolve(spec, "sec")?;
    let txt = std::fs::read_to_string(&path)?;
    let f: SecKeyFile =
        serde_json::from_str(&txt).map_err(|e| OpsecError::Header(format!("sec key json: {e}")))?;
    let raw = hex::decode(&f.secret_hex).map_err(|_| OpsecError::Header("sec key hex".into()))?;
    XwingSecret::from_bytes(&raw)
}

fn resolve(spec: &str, ext: &str) -> Result<PathBuf> {
    let spec = spec.strip_prefix('@').unwrap_or(spec);
    // Chemin direct ?
    let p = Path::new(spec);
    if p.exists() {
        return Ok(p.to_path_buf());
    }
    // Nom dans le keyring.
    let k = keys_dir()?.join(format!("{spec}.{ext}"));
    if k.exists() {
        return Ok(k);
    }
    Err(OpsecError::InvalidParam(format!(
        "clé '{spec}' introuvable (ni fichier ni keyring)"
    )))
}

/// Liste les entrées du keyring : (nom, fingerprint, a_un_sec).
pub fn list() -> Result<Vec<(String, String, bool)>> {
    let dir = keys_dir()?;
    let mut out = Vec::new();
    if let Ok(rd) = std::fs::read_dir(&dir) {
        for e in rd.flatten() {
            let p = e.path();
            if p.extension().and_then(|x| x.to_str()) == Some("pub")
                && let Ok(txt) = std::fs::read_to_string(&p)
                && let Ok(f) = serde_json::from_str::<PubKeyFile>(&txt)
            {
                let has_sec = p.with_extension("sec").exists();
                out.push((f.name, f.fingerprint, has_sec));
            }
        }
    }
    out.sort_by(|a, b| a.0.cmp(&b.0));
    Ok(out)
}

/// Enregistre une clé publique externe dans le keyring — pour chiffrer
/// vers quelqu'un sans avoir sa clé secrète.
/// `source` : chemin d'un fichier `.pub` OU hex brut de la clé X-Wing.
/// Retourne (chemin du .pub créé, fingerprint).
pub fn import_public(name: &str, source: &str) -> Result<(PathBuf, String)> {
    validate_name(name)?;
    let source = source.trim().trim_matches('"').trim_matches('\'');
    let pubk = if Path::new(source).exists() {
        load_public(source)?
    } else {
        let raw = hex::decode(source)
            .map_err(|_| OpsecError::InvalidParam("ni fichier .pub ni hex valide".into()))?;
        XwingPublic::from_bytes(&raw)?
    };
    let fp = pubk.fingerprint();
    let dir = keys_dir()?;
    std::fs::create_dir_all(&dir)?;
    let created = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let pubf = PubKeyFile {
        name: name.to_string(),
        kind: "xwing".into(),
        key_hex: hex::encode(pubk.to_bytes()),
        fingerprint: fp.clone(),
        created,
    };
    let pub_path = dir.join(format!("{name}.pub"));
    if pub_path.with_extension("sec").exists() {
        return Err(OpsecError::InvalidParam(
            "une paire locale existe déjà sous ce nom".into(),
        ));
    }
    std::fs::write(&pub_path, serde_json::to_string_pretty(&pubf).unwrap())?;
    Ok((pub_path, fp))
}

/// Supprime une paire du keyring.
pub fn delete(name: &str) -> Result<()> {
    let dir = keys_dir()?;
    for ext in ["pub", "sec"] {
        let p = dir.join(format!("{name}.{ext}"));
        if p.exists() {
            std::fs::remove_file(p)?;
        }
    }
    Ok(())
}
