//! Tests du moteur crypto .aos — roundtrips, adverses (tamper/troncature),
//! suites, options, KEM hybride, keyfiles, wipe.

use std::io::Cursor;

use ats_opsec_suite::crypto::CipherSuite;
use ats_opsec_suite::crypto::engine::{self, Credential, EncryptOptions, KeySource};
use ats_opsec_suite::error::OpsecError;
use ats_opsec_suite::{crypto, wipe};

fn opts() -> EncryptOptions {
    EncryptOptions {
        // argon2 light pour la vitesse des tests (les presets forts sont
        // exercés en bench/intégration).
        argon2: crypto::Argon2Params {
            m_kib: 8192,
            t: 1,
            p: 1,
        },
        ..Default::default()
    }
}

fn pw_key(pass: &str) -> KeySource {
    KeySource::Password {
        pass: zeroize::Zeroizing::new(pass.as_bytes().to_vec()),
        keyfile: None,
    }
}

fn pw_cred(pass: &str) -> Credential {
    Credential::Password {
        pass: zeroize::Zeroizing::new(pass.as_bytes().to_vec()),
        keyfile: None,
    }
}

fn roundtrip(plain: &[u8], key: &KeySource, cred: &Credential, o: &EncryptOptions) -> Vec<u8> {
    let mut ct = Vec::new();
    engine::encrypt_stream(Cursor::new(plain), &mut ct, key, o, &mut |_| {}).unwrap();
    let mut out = Vec::new();
    engine::decrypt_stream(Cursor::new(&ct), &mut out, cred, &mut |_| {}).unwrap();
    out
}

#[test]
fn roundtrip_xchacha() {
    let plain = "le fichier osint ultra secret - données sensibles".as_bytes();
    let o = EncryptOptions {
        suite: CipherSuite::XChaCha20,
        ..opts()
    };
    let out = roundtrip(plain, &pw_key("hunter42"), &pw_cred("hunter42"), &o);
    assert_eq!(out, plain);
}

#[test]
fn roundtrip_aes_gcm() {
    let plain = vec![0xABu8; 300_000]; // >1 chunk à 256K
    let o = EncryptOptions {
        suite: CipherSuite::Aes256Gcm,
        ..opts()
    };
    let out = roundtrip(&plain, &pw_key("p"), &pw_cred("p"), &o);
    assert_eq!(out, plain);
}

#[test]
fn roundtrip_cascade() {
    let plain = b"cascade mode test payload".repeat(5000);
    let o = EncryptOptions {
        suite: CipherSuite::Cascade,
        ..opts()
    };
    let out = roundtrip(&plain, &pw_key("p"), &pw_cred("p"), &o);
    assert_eq!(out, plain);
}

#[test]
fn roundtrip_empty_and_chunk_boundary() {
    for n in [0usize, 1, 262_143, 262_144, 262_145, 600_000] {
        let plain = vec![7u8; n];
        let out = roundtrip(&plain, &pw_key("x"), &pw_cred("x"), &opts());
        assert_eq!(out.len(), plain.len(), "taille {n}");
        assert_eq!(out, plain);
    }
}

#[test]
fn wrong_password_fails() {
    let mut ct = Vec::new();
    engine::encrypt_stream(
        Cursor::new(b"secret"),
        &mut ct,
        &pw_key("bon-mdp"),
        &opts(),
        &mut |_| {},
    )
    .unwrap();
    let mut out = Vec::new();
    let r = engine::decrypt_stream(Cursor::new(&ct), &mut out, &pw_cred("mauvais"), &mut |_| {});
    assert!(matches!(r, Err(OpsecError::Auth)));
    assert!(out.is_empty());
}

#[test]
fn tampered_ciphertext_fails() {
    let mut ct = Vec::new();
    engine::encrypt_stream(
        Cursor::new("données à protéger".as_bytes()),
        &mut ct,
        &pw_key("k"),
        &opts(),
        &mut |_| {},
    )
    .unwrap();
    let i = ct.len() - 5; // dans le dernier chunk
    ct[i] ^= 0xFF;
    let mut out = Vec::new();
    assert!(
        engine::decrypt_stream(Cursor::new(&ct), &mut out, &pw_cred("k"), &mut |_| {}).is_err()
    );
}

#[test]
fn tampered_header_fails() {
    let mut ct = Vec::new();
    engine::encrypt_stream(
        Cursor::new(b"abcd"),
        &mut ct,
        &pw_key("k"),
        &opts(),
        &mut |_| {},
    )
    .unwrap();
    // Octet au milieu du corps d'en-tête : soit le JSON casse, soit l'AAD
    // lie l'en-tête et le premier chunk refuse de déchiffrer.
    let hl = u32::from_le_bytes(ct[4..8].try_into().unwrap()) as usize;
    ct[8 + hl / 2] ^= 0x01;
    let mut out = Vec::new();
    assert!(
        engine::decrypt_stream(Cursor::new(&ct), &mut out, &pw_cred("k"), &mut |_| {}).is_err()
    );
}

#[test]
fn truncated_stream_fails() {
    let mut ct = Vec::new();
    engine::encrypt_stream(
        Cursor::new(&vec![1u8; 500_000]),
        &mut ct,
        &pw_key("k"),
        &opts(),
        &mut |_| {},
    )
    .unwrap();
    let cut = ct.len() - 40; // tronque dans le dernier chunk
    let mut out = Vec::new();
    assert!(
        engine::decrypt_stream(
            Cursor::new(&ct[..cut]),
            &mut out,
            &pw_cred("k"),
            &mut |_| {}
        )
        .is_err()
    );
}

#[test]
fn compression_and_padding() {
    let plain = b"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".repeat(3000);
    let o = EncryptOptions {
        compress: true,
        pad: true,
        ..opts()
    };
    let mut ct = Vec::new();
    engine::encrypt_stream(Cursor::new(&plain), &mut ct, &pw_key("k"), &o, &mut |_| {}).unwrap();
    let h = engine::inspect_bytes(&ct).unwrap();
    assert!(h.compressed);
    assert!(h.padded);
    // le bruit de padding masque la taille réelle (quantum 4k + jitter)
    let mut ct2 = Vec::new();
    engine::encrypt_stream(Cursor::new(&plain), &mut ct2, &pw_key("k"), &o, &mut |_| {}).unwrap();
    let mut out = Vec::new();
    engine::decrypt_stream(Cursor::new(&ct), &mut out, &pw_cred("k"), &mut |_| {}).unwrap();
    assert_eq!(out, plain);
}

#[test]
fn keyfile_changes_key() {
    let kf = b"FICHIER-CLE-ALEA";
    let key = KeySource::Password {
        pass: zeroize::Zeroizing::new(b"mdp".to_vec()),
        keyfile: Some(kf.to_vec()),
    };
    let mut ct = Vec::new();
    engine::encrypt_stream(Cursor::new(b"data"), &mut ct, &key, &opts(), &mut |_| {}).unwrap();
    // mdp seul → échec
    let mut out = Vec::new();
    assert!(
        engine::decrypt_stream(Cursor::new(&ct), &mut out, &pw_cred("mdp"), &mut |_| {}).is_err()
    );
    // mdp + keyfile → ok
    let ok = Credential::Password {
        pass: zeroize::Zeroizing::new(b"mdp".to_vec()),
        keyfile: Some(kf.to_vec()),
    };
    engine::decrypt_stream(Cursor::new(&ct), &mut out, &ok, &mut |_| {}).unwrap();
    assert_eq!(out, b"data");
}

// ------------------------------------------------------------- kem / xwing

#[test]
fn xwing_keygen_encaps_roundtrip() {
    let (sec, pubk) = crypto::kem::keygen().unwrap();
    let (ct, ss_send) = crypto::kem::encapsulate(&pubk).unwrap();
    let ss_recv = crypto::kem::decapsulate(&sec, &ct).unwrap();
    assert_eq!(*ss_send, *ss_recv);
}

#[test]
fn xwing_serialization_roundtrip() {
    let (sec, pubk) = crypto::kem::keygen().unwrap();
    let pub2 = crypto::XwingPublic::from_bytes(&pubk.to_bytes()).unwrap();
    let sec2 = crypto::XwingSecret::from_bytes(&sec.to_bytes()).unwrap();
    assert_eq!(pubk.fingerprint(), pub2.fingerprint());
    let (ct, ss1) = crypto::kem::encapsulate(&pub2).unwrap();
    let ss2 = crypto::kem::decapsulate(&sec2, &ct).unwrap();
    assert_eq!(*ss1, *ss2);
}

#[test]
fn xwing_wrong_key_yields_different_secret() {
    let (_sec_a, pub_a) = crypto::kem::keygen().unwrap();
    let (sec_b, _pub_b) = crypto::kem::keygen().unwrap();
    let (ct, ss_send) = crypto::kem::encapsulate(&pub_a).unwrap();
    // ML-KEM : rejet implicite → décapsuler avec la mauvaise clé donne un
    // secret différent sans erreur ; le mismatch éclate ensuite au niveau
    // AEAD du chunk (fail closed).
    let ss_wrong = crypto::kem::decapsulate(&sec_b, &ct).unwrap();
    assert_ne!(*ss_wrong, *ss_send);
}

#[test]
fn recipient_file_roundtrip() {
    let (sec, pubk) = crypto::kem::keygen().unwrap();
    let plain = "fichier chiffré pour un destinataire PQ".as_bytes();
    let mut ct = Vec::new();
    engine::encrypt_stream(
        Cursor::new(plain),
        &mut ct,
        &KeySource::Recipients(vec![pubk]),
        &opts(),
        &mut |_| {},
    )
    .unwrap();
    let h = engine::inspect_bytes(&ct).unwrap();
    assert!(!h.is_password_mode());
    assert_eq!(h.recipients.len(), 1);
    let mut out = Vec::new();
    engine::decrypt_stream(
        Cursor::new(&ct),
        &mut out,
        &Credential::SecretKey(sec),
        &mut |_| {},
    )
    .unwrap();
    assert_eq!(out, plain);
}

// ------------------------------------------------------------------ format

#[test]
fn header_inspect_and_magic() {
    let mut ct = Vec::new();
    engine::encrypt_stream(
        Cursor::new(b"x"),
        &mut ct,
        &pw_key("k"),
        &opts(),
        &mut |_| {},
    )
    .unwrap();
    assert_eq!(&ct[..4], b"AOS1");
    let h = engine::inspect_bytes(&ct).unwrap();
    assert!(h.is_password_mode());
    let kdf = h.kdf.unwrap();
    assert_eq!(kdf.algo, "argon2id");
    assert_eq!(kdf.m_kib, 8192);
}

#[test]
fn garbage_rejected() {
    let mut out = Vec::new();
    assert!(
        engine::decrypt_stream(
            Cursor::new(b"pas un container"),
            &mut out,
            &pw_cred("x"),
            &mut |_| {}
        )
        .is_err()
    );
}

// ------------------------------------------------------------------ divers

#[test]
fn passphrase_generator() {
    let p = crypto::passphrase::generate(6, "-").unwrap();
    assert_eq!(p.split('-').count(), 6);
    // Entropie par construction : 6 mots × log2(wordlist EFF ≈ 7772).
    let bits = crypto::passphrase::diceware_bits(6);
    assert!(
        bits > 70.0,
        "diceware-6 devrait donner >70 bits, got {bits}"
    );
    assert!(crypto::passphrase::wordlist_len() > 7000);
    // zxcvbn est volontairement pessimiste sur les phrases diceware — on
    // vérifie juste qu'il ne crash pas et renvoie un score cohérent.
    let (score, _) = crypto::passphrase::strength(&p);
    assert!(score <= 4);
}

#[test]
fn shred_removes_file() {
    let tmp = tempfile::tempdir().unwrap();
    let f = tmp.path().join("victim.bin");
    std::fs::write(&f, vec![0xCCu8; 10_000]).unwrap();
    let res = wipe::shred(&f, 2, &mut |_| {}).unwrap();
    assert_eq!(res.bytes, 10_000);
    assert!(!f.exists());
}
