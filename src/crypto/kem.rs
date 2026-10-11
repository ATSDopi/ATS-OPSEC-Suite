//! KEM hybride X-Wing : X25519 + ML-KEM-768 (FIPS 203).
//!
//! Combinateur selon draft-irtf-cfrg-xwing :
//! `ss = SHA3-256(ss_mlkem ‖ ss_x25519 ‖ ct_x25519 ‖ pk_x25519 ‖ LABEL)`
//! Une faille de l'une des deux moitiés ne compromet pas le secret.
//!
//! Sérialisation : clé secrète = seed ML-KEM 64o + x25519 32o (96o).

use ml_kem::{Decapsulate, Encapsulate, Kem, KeyExport, MlKem768};
use sha3::{Digest, Sha3_256};
use x25519_dalek::{PublicKey as XPublic, StaticSecret};
use zeroize::Zeroizing;

use crate::error::{OpsecError, Result};

/// Label X-Wing du draft (b"\.//^\").
const XWING_LABEL: &[u8] = b"\\.//^\\";

pub const XWING_PUB_LEN: usize = 1184 + 32;
pub const XWING_SEC_LEN: usize = 64 + 32;

type Ek = ml_kem::EncapsulationKey<MlKem768>;
type Dk = ml_kem::DecapsulationKey<MlKem768>;
type EkBytes = ml_kem::kem::Key<Ek>;
type SeedBytes = ml_kem::Seed;

#[derive(Debug, Clone)]
pub struct XwingPublic {
    /// Encapsulation key ML-KEM-768 (1184o).
    pub ek: Vec<u8>,
    /// Clé publique X25519 (32o).
    pub xpk: [u8; 32],
}

pub struct XwingSecret {
    /// Seed ML-KEM-768 (64o — expansion déterministe à la volée).
    pub seed: Zeroizing<[u8; 64]>,
    pub xsk: Zeroizing<[u8; 32]>,
}

/// Ciphertext côté en-tête : ct ML-KEM + clé publique X25519 éphémère.
#[derive(Debug, Clone)]
pub struct XwingCiphertext {
    pub mlkem_ct: Vec<u8>,
    pub eph_xpk: [u8; 32],
}

impl XwingPublic {
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut v = Vec::with_capacity(XWING_PUB_LEN);
        v.extend_from_slice(&self.ek);
        v.extend_from_slice(&self.xpk);
        v
    }

    pub fn from_bytes(b: &[u8]) -> Result<Self> {
        if b.len() != XWING_PUB_LEN {
            return Err(OpsecError::InvalidParam(format!(
                "clé publique xwing : {XWING_PUB_LEN}o attendus, {} reçus",
                b.len()
            )));
        }
        Ok(Self {
            ek: b[..1184].to_vec(),
            xpk: b[1184..].try_into().unwrap(),
        })
    }

    /// blake3(pub) tronqué — repère humain dans le keyring/TUI.
    pub fn fingerprint(&self) -> String {
        blake3::hash(&self.to_bytes()).to_hex().as_str()[..16].to_string()
    }

    fn ek_typed(&self) -> Result<Ek> {
        let arr: EkBytes = EkBytes::try_from(self.ek.as_slice())
            .map_err(|_| OpsecError::Crypto("clé ml-kem taille invalide".into()))?;
        Ek::new(&arr).map_err(|_| OpsecError::Crypto("clé ml-kem invalide".into()))
    }
}

impl XwingSecret {
    pub fn public(&self) -> Result<XwingPublic> {
        let dk = self.dk();
        let ek = dk.encapsulation_key().to_bytes().to_vec();
        let xsk = StaticSecret::from(*self.xsk);
        let xpk = XPublic::from(&xsk).to_bytes();
        Ok(XwingPublic { ek, xpk })
    }

    fn dk(&self) -> Dk {
        let seed: SeedBytes =
            SeedBytes::try_from(self.seed.as_slice()).expect("seed 64o validée à la construction");
        Dk::from_seed(seed)
    }

    pub fn to_bytes(&self) -> Zeroizing<Vec<u8>> {
        let mut v = Zeroizing::new(Vec::with_capacity(XWING_SEC_LEN));
        v.extend_from_slice(self.seed.as_slice());
        v.extend_from_slice(self.xsk.as_slice());
        v
    }

    pub fn from_bytes(b: &[u8]) -> Result<Self> {
        if b.len() != XWING_SEC_LEN {
            return Err(OpsecError::InvalidParam(format!(
                "clé secrète xwing : {XWING_SEC_LEN}o attendus, {} reçus",
                b.len()
            )));
        }
        Ok(Self {
            seed: Zeroizing::new(b[..64].try_into().unwrap()),
            xsk: Zeroizing::new(b[64..].try_into().unwrap()),
        })
    }
}

/// Keypair hybride. ML-KEM via son SysRng interne (feature getrandom),
/// X25519 via getrandom direct.
pub fn keygen() -> Result<(XwingSecret, XwingPublic)> {
    let (dk, ek) = MlKem768::generate_keypair();
    let mut xsk = [0u8; 32];
    getrandom::getrandom(&mut xsk).map_err(|e| OpsecError::Crypto(format!("rng: {e}")))?;
    let xpk = XPublic::from(&StaticSecret::from(xsk)).to_bytes();

    let seed: [u8; 64] = dk
        .to_seed()
        .map(|s| s.as_slice().try_into().expect("seed 64o"))
        .ok_or_else(|| OpsecError::Crypto("seed ml-kem absente".into()))?;

    Ok((
        XwingSecret {
            seed: Zeroizing::new(seed),
            xsk: Zeroizing::new(xsk),
        },
        XwingPublic {
            ek: ek.to_bytes().to_vec(),
            xpk,
        },
    ))
}

/// Encapsulation vers un destinataire → (ct de slot, secret partagé).
pub fn encapsulate(recipient: &XwingPublic) -> Result<(XwingCiphertext, Zeroizing<[u8; 32]>)> {
    let ek = recipient.ek_typed()?;
    let (mlkem_ct, ss_m) = ek.encapsulate();

    // X25519 : éphémère × publique statique du destinataire.
    let mut eph = [0u8; 32];
    getrandom::getrandom(&mut eph).map_err(|e| OpsecError::Crypto(format!("rng: {e}")))?;
    let eph_sk = StaticSecret::from(eph);
    let eph_pk = XPublic::from(&eph_sk).to_bytes();
    let ss_x = eph_sk.diffie_hellman(&XPublic::from(recipient.xpk));
    if !ss_x.was_contributory() {
        return Err(OpsecError::Crypto("x25519 non contributif".into()));
    }

    let ss = combine(mlkem_ss(&ss_m), ss_x.as_bytes(), &eph_pk, &recipient.xpk);
    Ok((
        XwingCiphertext {
            mlkem_ct: mlkem_ct.as_slice().to_vec(),
            eph_xpk: eph_pk,
        },
        ss,
    ))
}

/// Décapsulation côté destinataire.
pub fn decapsulate(sec: &XwingSecret, ct: &XwingCiphertext) -> Result<Zeroizing<[u8; 32]>> {
    let dk = sec.dk();
    let ss_m = dk
        .decapsulate_slice(&ct.mlkem_ct)
        .map_err(|_| OpsecError::Header("ct ml-kem taille invalide".into()))?;

    let xsk = StaticSecret::from(*sec.xsk);
    let ss_x = xsk.diffie_hellman(&XPublic::from(ct.eph_xpk));
    if !ss_x.was_contributory() {
        return Err(OpsecError::Crypto("x25519 non contributif".into()));
    }

    let xpk = sec.public()?.xpk;
    Ok(combine(mlkem_ss(&ss_m), ss_x.as_bytes(), &ct.eph_xpk, &xpk))
}

fn mlkem_ss(ss: &ml_kem::kem::SharedKey<MlKem768>) -> &[u8; 32] {
    ss.as_slice().try_into().expect("shared key 32o")
}

/// Combinateur X-Wing.
fn combine(
    ss_m: &[u8; 32],
    ss_x: &[u8; 32],
    ct_x: &[u8; 32],
    pk_x: &[u8; 32],
) -> Zeroizing<[u8; 32]> {
    let mut h = Sha3_256::new();
    h.update(ss_m);
    h.update(ss_x);
    h.update(ct_x);
    h.update(pk_x);
    h.update(XWING_LABEL);
    Zeroizing::new(h.finalize().into())
}
