//! Registre des AEAD disponibles — chaque `CipherKind` sait se décrire
//! (id sérialisé dans l'en-tête, label UI, note de sécurité, tailles de
//! nonce/clé) et construire sa couche `LayerImpl` prête à sceller.
//!
//! La **cascade** n'est pas un mode à part : c'est un `Vec<CipherKind>` de
//! longueur > 1 — l'ordre du vecteur EST l'ordre de scellement
//! (le premier = couche interne sur le clair, le dernier = externe).

use aes_gcm::aead::{Aead, AeadCore, KeyInit, Payload};
use aes_gcm::{Aes128Gcm, Aes256Gcm};
use aes_gcm_siv::Aes256GcmSiv;
use ascon_aead::AsconAead128;
use chacha20poly1305::XChaCha20Poly1305;
use zeroize::Zeroizing;

use aes_gcm_siv::aead as aead6;

use super::kdf::{self, KEY_LEN};
use crate::error::{OpsecError, Result};

// ------------------------------------------------------------------ kind

/// Un AEAD utilisable comme couche du container `.aos`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CipherKind {
    /// Référence par défaut — nonce 24o, rapide même sans AES-NI.
    XChaCha20,
    /// Standard industriel + accélération AES-NI.
    Aes256Gcm,
    /// Même mode, clé 128 bits.
    Aes128Gcm,
    /// GCM-SIV : résistant à la réutilisation de nonce (misuse-resistant).
    Aes256GcmSiv,
    /// AES-EAX : CMAC+CTR, nonce 16o.
    Aes256Eax,
    /// Deoxys-II-256-128 : tweakable cipher, gagnant CAESAR, misuse-res.
    DeoxysII256,
    /// Ascon-128 : standard NIST lightweight — petit, éprouvé.
    Ascon128,
    /// AEGIS-256 : très haut débit, nonce 32o (impl pure-Rust ici).
    Aegis256,
}

impl CipherKind {
    /// Tous les ciphers dans l'ordre d'affichage UI.
    pub const ALL: &'static [CipherKind] = &[
        CipherKind::XChaCha20,
        CipherKind::Aes256Gcm,
        CipherKind::Aes256GcmSiv,
        CipherKind::Aegis256,
        CipherKind::DeoxysII256,
        CipherKind::Aes256Eax,
        CipherKind::Aes128Gcm,
        CipherKind::Ascon128,
    ];

    /// Cascade "parano" par défaut (compat avec `CipherSuite::Cascade` v1).
    pub const DEFAULT_CASCADE: &'static [CipherKind] =
        &[CipherKind::XChaCha20, CipherKind::Aes256Gcm];

    /// Identifiant sérialisé dans l'en-tête `.aos`.
    pub fn id(self) -> &'static str {
        match self {
            Self::XChaCha20 => "xchacha20-poly1305",
            Self::Aes256Gcm => "aes-256-gcm",
            Self::Aes128Gcm => "aes-128-gcm",
            Self::Aes256GcmSiv => "aes-256-gcm-siv",
            Self::Aes256Eax => "aes-256-eax",
            Self::DeoxysII256 => "deoxys-ii-256-128",
            Self::Ascon128 => "ascon-128",
            Self::Aegis256 => "aegis-256",
        }
    }

    pub fn from_id(s: &str) -> Option<Self> {
        Self::ALL.iter().copied().find(|k| k.id() == s)
    }

    /// Tag de sécurité affiché dans l'UI.
    pub fn note(self) -> &'static str {
        match self {
            Self::XChaCha20 => "nonce 24B · fast sw",
            Self::Aes256Gcm => "aes-ni · industry std",
            Self::Aes128Gcm => "aes-ni · 128b key",
            Self::Aes256GcmSiv => "misuse-resistant",
            Self::Aes256Eax => "cmac+ctr · 16B nonce",
            Self::DeoxysII256 => "caesar winner · misuse-res",
            Self::Ascon128 => "nist lightweight · tiny",
            Self::Aegis256 => "very fast · 32B nonce",
        }
    }

    /// Octets de nonce attendus par la couche.
    pub fn nonce_len(self) -> usize {
        match self {
            Self::XChaCha20 => 24,
            Self::Aes256Gcm | Self::Aes128Gcm | Self::Aes256GcmSiv => 12,
            Self::Aes256Eax | Self::Ascon128 => 16,
            Self::DeoxysII256 => 15,
            Self::Aegis256 => 32,
        }
    }

    /// Octets de clé dérivés pour la couche.
    pub fn key_len(self) -> usize {
        match self {
            Self::Aes128Gcm | Self::Ascon128 => 16,
            Self::DeoxysII256 => 32,
            _ => 32,
        }
    }

    /// Construit la couche (clé HKDF dédiée : master+prefix+layer index).
    pub fn make_layer(
        self,
        master: &Zeroizing<[u8; KEY_LEN]>,
        prefix: &[u8; 16],
        index: usize,
    ) -> LayerImpl {
        let info = format!("aos/layer/{index}/{}", self.id());
        let key = kdf::expand_dyn(master, prefix, &info, self.key_len());
        match self {
            Self::XChaCha20 => LayerImpl::XChaCha(XChaCha20Poly1305::new_from_slice(&key).unwrap()),
            Self::Aes256Gcm => LayerImpl::Aes256Gcm(Aes256Gcm::new_from_slice(&key).unwrap()),
            Self::Aes128Gcm => LayerImpl::Aes128Gcm(Aes128Gcm::new_from_slice(&key).unwrap()),
            Self::Aes256GcmSiv => {
                LayerImpl::GcmSiv(<Aes256GcmSiv as aead6::KeyInit>::new_from_slice(&key).unwrap())
            }
            Self::Aes256Eax => {
                LayerImpl::Eax(<EaxAes as aead6::KeyInit>::new_from_slice(&key).unwrap())
            }
            Self::DeoxysII256 => LayerImpl::Deoxys(
                <deoxys::DeoxysII256 as aead6::KeyInit>::new_from_slice(&key).unwrap(),
            ),
            Self::Ascon128 => {
                LayerImpl::Ascon(<AsconAead128 as aead6::KeyInit>::new_from_slice(&key).unwrap())
            }
            Self::Aegis256 => {
                let mut k = [0u8; 32];
                k.copy_from_slice(&key[..32]);
                LayerImpl::Aegis(k)
            }
        }
    }
}

// ------------------------------------------------------------------ couche

type EaxAes = eax::Eax<aes::Aes256>;

/// GenericArray typée par le `NonceSize` d'un cipher `aead` 0.5.
fn nonce_for<C: AeadCore>(n: &[u8]) -> &aes_gcm::aead::Nonce<C> {
    aes_gcm::aead::Nonce::<C>::from_slice(n)
}

/// Seal pour la famille `aead` 0.6 (nonce typé via `Nonce<C>`).
fn seal6<C: aead6::Aead>(c: &C, nonce: &[u8], pt: &[u8], aad: &[u8]) -> Result<Vec<u8>> {
    let n: &aead6::Nonce<C> = nonce
        .try_into()
        .map_err(|_| OpsecError::Crypto("nonce len".into()))?;
    c.encrypt(n, aead6::Payload { msg: pt, aad })
        .map_err(|_| OpsecError::Crypto("aead seal".into()))
}

fn open6<C: aead6::Aead>(c: &C, nonce: &[u8], ct: &[u8], aad: &[u8]) -> Result<Vec<u8>> {
    let n: &aead6::Nonce<C> = nonce.try_into().map_err(|_| OpsecError::Auth)?;
    c.decrypt(n, aead6::Payload { msg: ct, aad })
        .map_err(|_| OpsecError::Auth)
}

/// Couche AEAD instanciée — `seal`/`open` par chunk avec le nonce dérivé
/// du compteur (unicité garantie par clé HKDF unique par (fichier, layer)).
pub enum LayerImpl {
    XChaCha(XChaCha20Poly1305),
    Aes256Gcm(Aes256Gcm),
    Aes128Gcm(Aes128Gcm),
    GcmSiv(Aes256GcmSiv),
    Eax(EaxAes),
    Deoxys(deoxys::DeoxysII256),
    Ascon(AsconAead128),
    /// AEGIS : API one-shot (pas de trait `aead`) — on garde juste la clé.
    Aegis([u8; 32]),
}

impl LayerImpl {
    pub fn seal(&self, nonce: &[u8], pt: &[u8], aad: &[u8]) -> Result<Vec<u8>> {
        let p = Payload { msg: pt, aad };
        match self {
            Self::XChaCha(c) => c
                .encrypt(nonce_for::<XChaCha20Poly1305>(nonce), p)
                .map_err(|_| OpsecError::Crypto("xchacha20 seal".into())),
            Self::Aes256Gcm(c) => c
                .encrypt(nonce_for::<Aes256Gcm>(nonce), p)
                .map_err(|_| OpsecError::Crypto("aes256gcm seal".into())),
            Self::Aes128Gcm(c) => c
                .encrypt(nonce_for::<Aes128Gcm>(nonce), p)
                .map_err(|_| OpsecError::Crypto("aes128gcm seal".into())),
            Self::GcmSiv(c) => seal6(c, nonce, pt, aad),
            Self::Eax(c) => seal6(c, nonce, pt, aad),
            Self::Deoxys(c) => seal6(c, nonce, pt, aad),
            Self::Ascon(c) => seal6(c, nonce, pt, aad),
            Self::Aegis(k) => {
                let n: [u8; 32] = nonce
                    .try_into()
                    .map_err(|_| OpsecError::Crypto("aegis nonce".into()))?;
                let (ct, tag) = aegis::aegis256::Aegis256::<16>::new(k, &n).encrypt(pt, aad);
                let mut out = ct;
                out.extend_from_slice(&tag);
                Ok(out)
            }
        }
    }

    pub fn open(&self, nonce: &[u8], ct: &[u8], aad: &[u8]) -> Result<Vec<u8>> {
        let p = Payload { msg: ct, aad };
        match self {
            Self::XChaCha(c) => c
                .decrypt(nonce_for::<XChaCha20Poly1305>(nonce), p)
                .map_err(|_| OpsecError::Auth),
            Self::Aes256Gcm(c) => c
                .decrypt(nonce_for::<Aes256Gcm>(nonce), p)
                .map_err(|_| OpsecError::Auth),
            Self::Aes128Gcm(c) => c
                .decrypt(nonce_for::<Aes128Gcm>(nonce), p)
                .map_err(|_| OpsecError::Auth),
            Self::GcmSiv(c) => open6(c, nonce, ct, aad),
            Self::Eax(c) => open6(c, nonce, ct, aad),
            Self::Deoxys(c) => open6(c, nonce, ct, aad),
            Self::Ascon(c) => open6(c, nonce, ct, aad),
            Self::Aegis(k) => {
                if ct.len() < 16 {
                    return Err(OpsecError::Auth);
                }
                let n: [u8; 32] = nonce.try_into().map_err(|_| OpsecError::Auth)?;
                let (body, tag) = ct.split_at(ct.len() - 16);
                let tag: [u8; 16] = tag.try_into().map_err(|_| OpsecError::Auth)?;
                aegis::aegis256::Aegis256::<16>::new(k, &n)
                    .decrypt(body, &tag, aad)
                    .map_err(|_| OpsecError::Auth)
            }
        }
    }
}
