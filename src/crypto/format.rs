//! Format de container `.aos` v1 :
//!
//! ```text
//! "AOS1" (4o) | header_len u32 LE | header JSON | chunk stream | padding?
//! chunk := u32 LE (bit31 = LAST, bits0-30 = ct_len) | ct (pt + tag 16o)
//! ```
//!
//! L'en-tête sérialisé est authentifié : son hash blake3 est passé en AAD
//! à chaque chunk AEAD → toute modification d'en-tête casse le chunk 1.

use serde::{Deserialize, Serialize};

use super::ciphers::CipherKind;
use super::{Argon2Params, CipherSuite, FORMAT_VERSION, MAGIC};
use crate::error::{OpsecError, Result};

pub const MAX_HEADER_LEN: u32 = 1024 * 1024;

/// Slot destinataire : file_key wrapée par un shared secret hybride X-Wing.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RecipientSlot {
    /// Éphémère X25519 de l'émetteur (hex).
    pub eph_x25519_hex: String,
    /// Ciphertext ML-KEM-768 encapsulé vers le destinataire (hex).
    pub mlkem_ct_hex: String,
    /// Nonce du wrap AEAD (hex).
    pub wrap_nonce_hex: String,
    /// file_key chiffrée (hex, 32o + tag 16o).
    pub wrapped_key_hex: String,
    /// Fingerprint blake3 de la clé publique destinataire (repère UI).
    pub fingerprint: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KdfBlock {
    pub algo: String,
    pub m_kib: u32,
    pub t: u32,
    pub p: u32,
    pub salt_hex: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AosHeader {
    pub v: u16,
    /// Étiquette compat v1 — `ciphers` est la source de vérité.
    pub suite: CipherSuite,
    /// Couches AEAD ordonnées (interne → externe). Vide = repli `suite`.
    #[serde(default)]
    pub ciphers: Vec<String>,
    pub chunk_size: u32,
    /// Préfixe de nonce aléatoire par fichier (hex 16o).
    pub nonce_prefix_hex: String,
    /// Mode mot de passe : présent ⇔ auth par passphrase.
    #[serde(default)]
    pub kdf: Option<KdfBlock>,
    /// Mode destinataire : slots X-Wing.
    #[serde(default)]
    pub recipients: Vec<RecipientSlot>,
    #[serde(default)]
    pub compressed: bool,
    #[serde(default)]
    pub padded: bool,
    /// Le contenu déchiffré est une archive tar (multi-fichiers/dossier).
    #[serde(default)]
    pub packed: bool,
}

impl AosHeader {
    pub fn new(ciphers: &[CipherKind], chunk_size: u32, nonce_prefix: [u8; 16]) -> Self {
        Self {
            v: FORMAT_VERSION,
            suite: CipherSuite::from_kinds(ciphers),
            ciphers: ciphers.iter().map(|k| k.id().to_string()).collect(),
            chunk_size,
            nonce_prefix_hex: hex::encode(nonce_prefix),
            kdf: None,
            recipients: Vec::new(),
            compressed: false,
            padded: false,
            packed: false,
        }
    }

    /// Couches AEAD ordonnées du container (repli `suite` pour v1 initial).
    pub fn cipher_kinds(&self) -> Result<Vec<CipherKind>> {
        if self.ciphers.is_empty() {
            return Ok(self.suite.to_kinds());
        }
        self.ciphers
            .iter()
            .map(|id| {
                CipherKind::from_id(id)
                    .ok_or_else(|| OpsecError::Header(format!("cipher inconnu: {id}")))
            })
            .collect()
    }

    pub fn set_kdf(&mut self, params: &Argon2Params, salt: &[u8]) {
        self.kdf = Some(KdfBlock {
            algo: "argon2id".into(),
            m_kib: params.m_kib,
            t: params.t,
            p: params.p,
            salt_hex: hex::encode(salt),
        });
    }

    fn decode_prefix(&self) -> Result<[u8; 16]> {
        let b = hex::decode(&self.nonce_prefix_hex)
            .map_err(|_| OpsecError::Header("nonce_prefix hex invalide".into()))?;
        b.try_into()
            .map_err(|_| OpsecError::Header("nonce_prefix doit faire 16o".into()))
    }
}

/// Écrit magic + len + header sérialisé ; retourne les octets d'en-tête bruts
/// (nécessaires pour l'AAD des chunks).
pub fn write_header<W: std::io::Write>(w: &mut W, h: &AosHeader) -> Result<Vec<u8>> {
    let body = serde_json::to_vec(h).map_err(|e| OpsecError::Header(e.to_string()))?;
    w.write_all(MAGIC)?;
    w.write_all(&(body.len() as u32).to_le_bytes())?;
    w.write_all(&body)?;
    Ok(body)
}

/// Lit magic + len + header ; retourne (header, octets bruts).
pub fn read_header<R: std::io::Read>(r: &mut R) -> Result<(AosHeader, Vec<u8>)> {
    let mut magic = [0u8; 4];
    r.read_exact(&mut magic)?;
    if &magic != MAGIC {
        return Err(OpsecError::BadMagic);
    }
    let mut len_b = [0u8; 4];
    r.read_exact(&mut len_b)?;
    let len = u32::from_le_bytes(len_b);
    if len == 0 || len > MAX_HEADER_LEN {
        return Err(OpsecError::Header(format!("header_len invalide: {len}")));
    }
    let mut body = vec![0u8; len as usize];
    r.read_exact(&mut body)?;
    let h: AosHeader =
        serde_json::from_slice(&body).map_err(|e| OpsecError::Header(format!("json: {e}")))?;
    if h.v != FORMAT_VERSION {
        return Err(OpsecError::Header(format!(
            "version non supportée: {}",
            h.v
        )));
    }
    h.decode_prefix()?;
    Ok((h, body))
}

impl AosHeader {
    pub fn nonce_prefix(&self) -> Result<[u8; 16]> {
        self.decode_prefix()
    }

    pub fn is_password_mode(&self) -> bool {
        self.kdf.is_some()
    }

    pub fn is_recipient_mode(&self) -> bool {
        !self.recipients.is_empty()
    }
}
