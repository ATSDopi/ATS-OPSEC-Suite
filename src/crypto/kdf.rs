//! Dérivation de clés : Argon2id paramétrable (maître-clé) + HKDF-SHA256
//! (clés de couches). `getrandom` seul pour les sels — jamais thread_rng.

use hkdf::Hkdf;
use sha2::Sha256;
use zeroize::Zeroizing;

use super::Argon2Params;
use crate::error::{OpsecError, Result};

pub const SALT_LEN: usize = 16;
pub const KEY_LEN: usize = 32;

/// matériau = password (optionnellement + `blake3(keyfile)` concaténé).
pub fn password_material(password: &[u8], keyfile: Option<&[u8]>) -> Zeroizing<Vec<u8>> {
    let mut m = Zeroizing::new(password.to_vec());
    if let Some(kf) = keyfile {
        m.extend_from_slice(b"\x00keyfile\x00");
        m.extend_from_slice(blake3::hash(kf).as_bytes());
    }
    m
}

/// Argon2id → clé maître 32 o. `OpsecError::Crypto` si paramètres hors bornes.
pub fn derive_master(
    material: &[u8],
    salt: &[u8; SALT_LEN],
    p: &Argon2Params,
) -> Result<Zeroizing<[u8; KEY_LEN]>> {
    let params = argon2::Params::new(p.m_kib, p.t, p.p, Some(KEY_LEN))
        .map_err(|e| OpsecError::InvalidParam(format!("argon2: {e}")))?;
    let ctx = argon2::Argon2::new(argon2::Algorithm::Argon2id, argon2::Version::V0x13, params);
    let mut out = Zeroizing::new([0u8; KEY_LEN]);
    ctx.hash_password_into(material, salt, out.as_mut())
        .map_err(|e| OpsecError::Crypto(format!("argon2: {e}")))?;
    Ok(out)
}

/// HKDF-SHA256(master, salt=nonce_prefix, info) → clé de couche 32 o.
pub fn expand(master: &[u8; KEY_LEN], salt: &[u8], info: &str) -> Zeroizing<[u8; KEY_LEN]> {
    let hk = Hkdf::<Sha256>::new(Some(salt), master);
    let mut out = Zeroizing::new([0u8; KEY_LEN]);
    // 32 o ≤ 255·32 — expand ne peut pas échouer.
    hk.expand(info.as_bytes(), out.as_mut())
        .expect("hkdf expand 32 bytes");
    out
}

/// Sel aléatoire via CSPRNG OS.
pub fn random_salt() -> Result<[u8; SALT_LEN]> {
    let mut s = [0u8; SALT_LEN];
    getrandom::getrandom(&mut s).map_err(|e| OpsecError::Crypto(format!("rng: {e}")))?;
    Ok(s)
}

pub fn random_bytes<const N: usize>() -> Result<[u8; N]> {
    let mut b = [0u8; N];
    getrandom::getrandom(&mut b).map_err(|e| OpsecError::Crypto(format!("rng: {e}")))?;
    Ok(b)
}
