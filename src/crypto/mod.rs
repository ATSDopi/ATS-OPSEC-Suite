//! Moteur cryptographique — staged v0.1 (types + format), implémentation v0.2.
//!
//! Voir docs/SPEC.md §2.1 : format `.aos`, STREAM chunked, cascade AEAD,
//! Argon2id paramétrable, hybride X25519+ML-KEM-768.

use serde::{Deserialize, Serialize};

/// Magic bytes du container auto-décrit.
pub const MAGIC: &[u8; 4] = b"AOS1";
/// Version du format de container.
pub const FORMAT_VERSION: u16 = 1;
/// Taille de chunk par défaut pour le STREAM AEAD (256 Kio).
pub const DEFAULT_CHUNK_SIZE: u32 = 256 * 1024;

/// Suite de chiffrement sélectionnable.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum CipherSuite {
    XChaCha20,
    Aes256Gcm,
    /// XChaCha20-Poly1305 encapsulé dans AES-256-GCM (AEAD imbriqués par chunk).
    Cascade,
}

impl CipherSuite {
    pub const ALL: &'static [CipherSuite] = &[
        CipherSuite::XChaCha20,
        CipherSuite::Aes256Gcm,
        CipherSuite::Cascade,
    ];

    pub fn label(self) -> &'static str {
        match self {
            CipherSuite::XChaCha20 => "xchacha20-poly1305",
            CipherSuite::Aes256Gcm => "aes-256-gcm",
            CipherSuite::Cascade => "xchacha20+aes256gcm",
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
    /// Profil « paranoid » : 512 Mio / 4 / 4 (calibrer via `bench` en v0.2).
    pub const PARANOID: Self = Self {
        m_kib: 512 * 1024,
        t: 4,
        p: 4,
    };
}

/// En-tête authentifié du container `.aos` — sérialisé JSON, préfixé par
/// magic + longueur u32 LE. Tout champ nécessaire au déchiffrement y figure.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AosHeader {
    pub v: u16,
    pub suite: CipherSuite,
    pub kdf: Argon2Params,
    pub salt_hex: String,
    pub chunk_size: u32,
    pub nonce_prefix_hex: String,
    pub compressed: bool,
    pub padded: bool,
}

/// Module crypto — volontairement non implémenté en v0.1 (TUI d'abord).
pub fn staged_notice() -> &'static str {
    "crypto engine staged for v0.2 — see docs/SPEC.md"
}
