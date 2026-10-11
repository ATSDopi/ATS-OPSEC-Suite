//! Moteur cryptographique — v0.2.
//!
//! Format `.aos` : `format.rs` · STREAM AEAD : `engine.rs` · KDF : `kdf.rs`
//! · KEM hybride X-Wing : `kem.rs` · keyring : `keys.rs` · diceware :
//! `passphrase.rs`. Voir docs/SPEC.md §2.1 pour le design complet.

pub mod ciphers;
pub mod engine;
pub mod format;
pub mod kdf;
pub mod kem;
pub mod keys;
pub mod pack;
pub mod passphrase;

use serde::{Deserialize, Serialize};

/// Magic bytes du container auto-décrit.
pub const MAGIC: &[u8; 4] = b"AOS1";
/// Version du format de container.
pub const FORMAT_VERSION: u16 = 1;
/// Taille de chunk par défaut pour le STREAM AEAD (256 Kio).
pub const DEFAULT_CHUNK_SIZE: u32 = 256 * 1024;

/// Étiquette de suite conservée pour la **compat v1** des en-têtes
/// (les containers écrits avant le registre `CipherKind`). La vérité
/// est désormais le champ `ciphers` de l'en-tête.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum CipherSuite {
    XChaCha20,
    Aes256Gcm,
    /// XChaCha20-Poly1305 encapsulé dans AES-256-GCM (AEAD imbriqués par chunk).
    Cascade,
}

impl CipherSuite {
    /// Repli pour containers écrits sans champ `ciphers` (v1 initiale).
    pub fn to_kinds(self) -> Vec<ciphers::CipherKind> {
        use ciphers::CipherKind as K;
        match self {
            Self::XChaCha20 => vec![K::XChaCha20],
            Self::Aes256Gcm => vec![K::Aes256Gcm],
            Self::Cascade => K::DEFAULT_CASCADE.to_vec(),
        }
    }

    /// Étiquette compat écrite dans les nouveaux containers.
    pub fn from_kinds(kinds: &[ciphers::CipherKind]) -> Self {
        use ciphers::CipherKind as K;
        match kinds {
            [K::XChaCha20] => Self::XChaCha20,
            [K::Aes256Gcm] => Self::Aes256Gcm,
            _ => Self::Cascade,
        }
    }

    pub fn label(self) -> &'static str {
        match self {
            CipherSuite::XChaCha20 => "xchacha20-poly1305",
            CipherSuite::Aes256Gcm => "aes-256-gcm",
            CipherSuite::Cascade => "cascade",
        }
    }
}

/// Paramètres Argon2id — entièrement exposés en mode Expert.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct Argon2Params {
    /// Mémoire en Kio.
    pub m_kib: u32,
    /// Itérations.
    pub t: u32,
    /// Lanes (parallélisme).
    pub p: u32,
}

impl Default for Argon2Params {
    /// Défaut « Standard » : 64 Mio / 3 itérations / 4 lanes (RFC 9106).
    fn default() -> Self {
        Self {
            m_kib: 64 * 1024,
            t: 3,
            p: 4,
        }
    }
}

impl Argon2Params {
    /// Profil « paranoid » : 512 Mio / 4 / 4 (calibrer via `bench`).
    pub const PARANOID: Self = Self {
        m_kib: 512 * 1024,
        t: 4,
        p: 4,
    };

    /// Bornes acceptées par Argon2 (et par notre UI).
    pub fn clamp(&mut self) {
        self.m_kib = self.m_kib.clamp(8 * 1024, 2 * 1024 * 1024);
        self.t = self.t.clamp(1, 10);
        self.p = self.p.clamp(1, 8);
    }
}

pub use ciphers::CipherKind;
pub use engine::{
    Credential, EncryptOptions, KeySource, decrypt_file, decrypt_stream, encrypt_file,
    encrypt_paths, encrypt_stream, inspect, inspect_bytes,
};
pub use format::AosHeader;
pub use kem::{XwingPublic, XwingSecret};
