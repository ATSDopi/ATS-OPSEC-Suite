//! Moteur de chiffrement STREAM chunked — jamais le fichier entier en RAM.
//!
//! ```text
//! chunk i : flags_len u32 LE (bit31=LAST, bits0-30=ct_len) | ct_i
//! ct_i    = AEAD(pt_i)  |  cascade: AES-GCM(XChaCha20(pt_i))
//! nonce_i = counter u64 BE (unicité garantie : clé fraîche par fichier
//!          dérivée via HKDF saltée par nonce_prefix aléatoire)
//! aad     = blake3(header sérialisé) → en-tête authentifié
//! ```
//!
//! Règles SPEC §5 : tags vérifiés AVANT d'écrire du clair (tmp + rename),
//! nonces jamais réutilisés, zéroisation des buffers.

use std::fs::{self, File};
use std::io::{BufWriter, Read, Write};
use std::path::{Path, PathBuf};

use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::{Aes256Gcm, Nonce as GcmNonce};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use zeroize::Zeroizing;

use super::format::{self, AosHeader, RecipientSlot};
use super::kdf::{self, KEY_LEN};
use super::{Argon2Params, CipherSuite, DEFAULT_CHUNK_SIZE, kem};
use crate::error::{OpsecError, Result};

const TAG_LEN: usize = 16;
const LAST_BIT: u32 = 1 << 31;
const PAD_BLOCK: u64 = 64 * 1024;

// ---------------------------------------------------------------- options

#[derive(Debug, Clone)]
pub struct EncryptOptions {
    pub suite: CipherSuite,
    pub argon2: Argon2Params,
    pub compress: bool,
    pub pad: bool,
    pub chunk_size: u32,
}

impl Default for EncryptOptions {
    fn default() -> Self {
        Self {
            suite: CipherSuite::XChaCha20,
            argon2: Argon2Params::default(),
            compress: false,
            pad: false,
            chunk_size: DEFAULT_CHUNK_SIZE,
        }
    }
}

/// Comment la clé maître est obtenue au chiffrement.
pub enum KeySource {
    /// Mot de passe (+ keyfile éventuel) → Argon2id.
    Password {
        pass: Zeroizing<Vec<u8>>,
        keyfile: Option<Vec<u8>>,
    },
    /// Destinataires hybrides : clé de fichier aléatoire wrapée par slot.
    Recipients(Vec<kem::XwingPublic>),
}

/// Comment déchiffrer.
pub enum Credential {
    Password {
        pass: Zeroizing<Vec<u8>>,
        keyfile: Option<Vec<u8>>,
    },
    /// Clé secrète X-Wing (keyring).
    SecretKey(kem::XwingSecret),
}

// ---------------------------------------------------------------- stream

/// Chiffre `src` vers `dst`. `progress(done_plain_bytes)` par chunk.
pub fn encrypt_stream<R: Read, W: Write>(
    src: R,
    dst: W,
    key: &KeySource,
    opts: &EncryptOptions,
    progress: &mut dyn FnMut(u64),
) -> Result<AosHeader> {
    let mut dst = CountWriter::new(dst);
    let nonce_prefix: [u8; 16] = kdf::random_bytes()?;
    let mut header = AosHeader::new(opts.suite, opts.chunk_size, nonce_prefix);
    header.compressed = opts.compress;
    header.padded = opts.pad;

    // Clé maître selon le mode.
    let master: Zeroizing<[u8; KEY_LEN]> = match key {
        KeySource::Password { pass, keyfile } => {
            let salt = kdf::random_salt()?;
            header.set_kdf(&opts.argon2, &salt);
            let material = kdf::password_material(pass, keyfile.as_deref());
            kdf::derive_master(&material, &salt, &opts.argon2)?
        }
        KeySource::Recipients(pubs) => {
            if pubs.is_empty() {
                return Err(OpsecError::InvalidParam("aucun destinataire".into()));
            }
            let file_key = Zeroizing::new(kdf::random_bytes::<32>()?);
            for p in pubs {
                header.recipients.push(wrap_slot(p, &file_key)?);
            }
            file_key
        }
    };

    // En-tête puis AAD = blake3(header sérialisé).
    let raw = format::write_header(&mut dst, &header)?;
    let aad = blake3::hash(&raw);
    let aad: &[u8] = aad.as_bytes();

    let layers = Layers::new(opts.suite, &master, &nonce_prefix);

    // Compression en amont du chiffrement (stream).
    let mut reader: Box<dyn Read> = if opts.compress {
        Box::new(zstd::stream::read::Encoder::new(src, 3)?)
    } else {
        Box::new(src)
    };

    let mut buf = Zeroizing::new(vec![0u8; opts.chunk_size as usize]);
    let mut counter: u64 = 0;
    let mut done: u64 = 0;
    loop {
        // Remplir le buffer (zstd peut produire des short reads).
        let mut n = 0;
        while n < buf.len() {
            match reader.read(&mut buf[n..])? {
                0 => break,
                r => n += r,
            }
        }
        let last = n < buf.len();
        // n==0 ⇒ last=true ⇒ chunk vide final — couvre input vide et
        // multiples exacts de chunk_size (toujours un chunk LAST).
        let ct = layers.seal(counter, &buf[..n], aad)?;
        write_chunk(&mut dst, &ct, last)?;
        counter += 1;
        done += n as u64;
        progress(done);
        if last {
            break;
        }
    }

    // Padding de taille — bruit après le stream (non authentifié).
    if opts.pad {
        let written = dst.count();
        let to_block = PAD_BLOCK - (written % PAD_BLOCK);
        let mut extra = [0u8; 8];
        getrandom::getrandom(&mut extra).map_err(|e| OpsecError::Crypto(format!("rng: {e}")))?;
        let jitter = (u64::from_le_bytes(extra) % PAD_BLOCK) as usize;
        let pad_len = to_block as usize + jitter;
        let mut pad = Zeroizing::new(vec![0u8; pad_len]);
        getrandom::getrandom(&mut pad).map_err(|e| OpsecError::Crypto(format!("rng: {e}")))?;
        dst.write_all(&pad)?;
    }
    dst.flush()?;
    Ok(header)
}

/// Déchiffre un container `.aos` vers `dst`.
pub fn decrypt_stream<R: Read, W: Write>(
    mut src: R,
    dst: W,
    cred: &Credential,
    progress: &mut dyn FnMut(u64),
) -> Result<AosHeader> {
    let (header, raw) = format::read_header(&mut src)?;
    let aad = blake3::hash(&raw);
    let aad: &[u8] = aad.as_bytes();
    let nonce_prefix = header.nonce_prefix()?;

    let master: Zeroizing<[u8; KEY_LEN]> = match cred {
        Credential::Password { pass, keyfile } => {
            let k = header
                .kdf
                .as_ref()
                .ok_or_else(|| OpsecError::Header("container en mode destinataire".into()))?;
            let salt: [u8; 16] = hex::decode(&k.salt_hex)
                .map_err(|_| OpsecError::Header("salt hex invalide".into()))?
                .try_into()
                .map_err(|_| OpsecError::Header("salt doit faire 16o".into()))?;
            let params = Argon2Params {
                m_kib: k.m_kib,
                t: k.t,
                p: k.p,
            };
            let material = kdf::password_material(pass, keyfile.as_deref());
            kdf::derive_master(&material, &salt, &params)?
        }
        Credential::SecretKey(sec) => {
            let mut found = None;
            for slot in &header.recipients {
                if let Ok(fk) = unwrap_slot(sec, slot) {
                    found = Some(fk);
                    break;
                }
            }
            found.ok_or(OpsecError::Auth)?
        }
    };

    let layers = Layers::new(header.suite, &master, &nonce_prefix);

    // Décompression côté écriture si le container est compressé.
    let mut writer: Box<dyn Write + '_> = if header.compressed {
        Box::new(zstd::stream::write::Decoder::new(dst)?)
    } else {
        Box::new(dst)
    };

    let mut counter: u64 = 0;
    let mut done: u64 = 0;
    loop {
        let mut fl = [0u8; 4];
        match src.read_exact(&mut fl) {
            Ok(()) => {}
            Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => {
                return Err(OpsecError::Header(
                    "stream tronqué — chunk LAST manquant".into(),
                ));
            }
            Err(e) => return Err(e.into()),
        }
        let word = u32::from_le_bytes(fl);
        let last = word & LAST_BIT != 0;
        let ct_len = (word & !LAST_BIT) as usize;
        // cascade = 2 tags + marge ; single = 1 tag
        let max_ct = header.chunk_size as usize + TAG_LEN * 2 + 8;
        if ct_len < TAG_LEN || ct_len > max_ct {
            return Err(OpsecError::Header(format!(
                "chunk {counter} : longueur invalide ({ct_len})"
            )));
        }
        let mut ct = Zeroizing::new(vec![0u8; ct_len]);
        src.read_exact(&mut ct)
            .map_err(|_| OpsecError::Header("stream tronqué dans chunk".into()))?;
        let pt = layers.open(counter, &ct, aad)?;
        writer.write_all(&pt)?;
        counter += 1;
        done += pt.len() as u64;
        progress(done);
        if last {
            break;
        }
    }
    writer.flush()?;
    Ok(header)
}

// ---------------------------------------------------------------- fichiers

/// Chiffre un fichier → `.aos` (tmp + rename atomique).
pub fn encrypt_file(
    input: &Path,
    output: &Path,
    key: &KeySource,
    opts: &EncryptOptions,
    progress: &mut dyn FnMut(u64),
) -> Result<PathBuf> {
    let src = File::open(input)?;
    let tmp = tmp_name(output, "aos.tmp");
    {
        let dst = BufWriter::new(File::create(&tmp)?);
        encrypt_stream(src, dst, key, opts, progress).inspect_err(|_| {
            let _ = fs::remove_file(&tmp);
        })?;
    }
    fs::rename(&tmp, output)?;
    Ok(output.to_path_buf())
}

/// Déchiffre un `.aos` → sortie via tmp + rename (vérifier avant d'écrire).
pub fn decrypt_file(
    input: &Path,
    output: &Path,
    cred: &Credential,
    progress: &mut dyn FnMut(u64),
) -> Result<PathBuf> {
    let src = File::open(input)?;
    let tmp = tmp_name(output, "dec.tmp");
    {
        let dst = BufWriter::new(File::create(&tmp)?);
        decrypt_stream(src, dst, cred, progress).inspect_err(|_| {
            let _ = fs::remove_file(&tmp);
        })?;
    }
    fs::rename(&tmp, output)?;
    Ok(output.to_path_buf())
}

/// Lit juste l'en-tête d'un container.
pub fn inspect(path: &Path) -> Result<AosHeader> {
    let mut f = File::open(path)?;
    let (h, _) = format::read_header(&mut f)?;
    Ok(h)
}

/// Inspection d'un container en mémoire (tests, analyses).
pub fn inspect_bytes(b: &[u8]) -> Result<AosHeader> {
    let mut cur = std::io::Cursor::new(b);
    let (h, _) = format::read_header(&mut cur)?;
    Ok(h)
}

/// Nom temporaire aléatoire à côté de la sortie (évite collisions).
fn tmp_name(out: &Path, tag: &str) -> PathBuf {
    let mut n = [0u8; 4];
    let _ = getrandom::getrandom(&mut n);
    out.with_extension(format!("{}.{}", hex::encode(n), tag))
}

// ---------------------------------------------------------------- interne

/// Compte les octets écrits (pour le padding de taille).
struct CountWriter<W: Write> {
    inner: W,
    n: u64,
}
impl<W: Write> CountWriter<W> {
    fn new(inner: W) -> Self {
        Self { inner, n: 0 }
    }
    fn count(&self) -> u64 {
        self.n
    }
}
impl<W: Write> Write for CountWriter<W> {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        let n = self.inner.write(buf)?;
        self.n += n as u64;
        Ok(n)
    }
    fn flush(&mut self) -> std::io::Result<()> {
        self.inner.flush()
    }
}

/// Couche(s) AEAD selon la suite choisie.
trait AeadBox {
    /// 24 (XChaCha20) ou 12 (AES-GCM).
    fn nonce_len(&self) -> usize;
    fn seal(&self, nonce: &[u8], pt: &[u8], aad: &[u8]) -> Result<Vec<u8>>;
    fn open(&self, nonce: &[u8], ct: &[u8], aad: &[u8]) -> Result<Vec<u8>>;
}

struct XChaCha(XChaCha20Poly1305);
struct AesGcm(Aes256Gcm);

impl AeadBox for XChaCha {
    fn nonce_len(&self) -> usize {
        24
    }
    fn seal(&self, nonce: &[u8], pt: &[u8], aad: &[u8]) -> Result<Vec<u8>> {
        self.0
            .encrypt(XNonce::from_slice(nonce), Payload { msg: pt, aad })
            .map_err(|_| OpsecError::Crypto("xchacha20 encrypt".into()))
    }
    fn open(&self, nonce: &[u8], ct: &[u8], aad: &[u8]) -> Result<Vec<u8>> {
        self.0
            .decrypt(XNonce::from_slice(nonce), Payload { msg: ct, aad })
            .map_err(|_| OpsecError::Auth)
    }
}

impl AeadBox for AesGcm {
    fn nonce_len(&self) -> usize {
        12
    }
    fn seal(&self, nonce: &[u8], pt: &[u8], aad: &[u8]) -> Result<Vec<u8>> {
        self.0
            .encrypt(GcmNonce::from_slice(nonce), Payload { msg: pt, aad })
            .map_err(|_| OpsecError::Crypto("aes-gcm encrypt".into()))
    }
    fn open(&self, nonce: &[u8], ct: &[u8], aad: &[u8]) -> Result<Vec<u8>> {
        self.0
            .decrypt(GcmNonce::from_slice(nonce), Payload { msg: ct, aad })
            .map_err(|_| OpsecError::Auth)
    }
}

enum Layers {
    Single(Box<dyn AeadBox>),
    /// inner = XChaCha20-Poly1305, outer = AES-256-GCM.
    Cascade(Box<dyn AeadBox>, Box<dyn AeadBox>),
}

impl Layers {
    fn new(suite: CipherSuite, master: &[u8; KEY_LEN], prefix: &[u8; 16]) -> Self {
        let kx = kdf::expand(master, prefix, "aos/layer/xchacha20");
        let ka = kdf::expand(master, prefix, "aos/layer/aes256gcm");
        match suite {
            CipherSuite::XChaCha20 => {
                Layers::Single(Box::new(XChaCha(XChaCha20Poly1305::new((&*kx).into()))))
            }
            CipherSuite::Aes256Gcm => {
                Layers::Single(Box::new(AesGcm(Aes256Gcm::new((&*ka).into()))))
            }
            CipherSuite::Cascade => Layers::Cascade(
                Box::new(XChaCha(XChaCha20Poly1305::new((&*kx).into()))),
                Box::new(AesGcm(Aes256Gcm::new((&*ka).into()))),
            ),
        }
    }

    fn seal(&self, counter: u64, pt: &[u8], aad: &[u8]) -> Result<Vec<u8>> {
        match self {
            Layers::Single(l) => {
                l.seal(&nonce_of(counter, l.nonce_len())[..l.nonce_len()], pt, aad)
            }
            Layers::Cascade(inner, outer) => {
                let ct1 = inner.seal(&nonce_of(counter, 24)[..inner.nonce_len()], pt, aad)?;
                outer.seal(&nonce_of(counter, 24)[..outer.nonce_len()], &ct1, aad)
            }
        }
    }

    fn open(&self, counter: u64, ct: &[u8], aad: &[u8]) -> Result<Vec<u8>> {
        match self {
            Layers::Single(l) => {
                l.open(&nonce_of(counter, l.nonce_len())[..l.nonce_len()], ct, aad)
            }
            Layers::Cascade(inner, outer) => {
                let ct1 = outer.open(&nonce_of(counter, 24)[..outer.nonce_len()], ct, aad)?;
                inner.open(&nonce_of(counter, 24)[..inner.nonce_len()], &ct1, aad)
            }
        }
    }
}

/// Nonce pour la couche : compteur u64 BE dans les 8 derniers octets,
/// zéros avant, tronqué à `len` (12 AES-GCM / 24 XChaCha).
/// Unicité garantie : la clé de couche est HKDF-saltée au nonce_prefix
/// aléatoire de l'en-tête → (clé, nonce) jamais réutilisée.
fn nonce_of(counter: u64, len: usize) -> Vec<u8> {
    let mut n = vec![0u8; len];
    n[len - 8..].copy_from_slice(&counter.to_be_bytes());
    n
}

fn write_chunk<W: Write>(w: &mut W, ct: &[u8], last: bool) -> Result<()> {
    let word = (ct.len() as u32) | if last { LAST_BIT } else { 0 };
    w.write_all(&word.to_le_bytes())?;
    w.write_all(ct)?;
    Ok(())
}

/// Wrappe la clé de fichier pour un destinataire X-Wing.
fn wrap_slot(recipient: &kem::XwingPublic, file_key: &[u8; KEY_LEN]) -> Result<RecipientSlot> {
    let (ct, ss) = kem::encapsulate(recipient)?;
    let wrap_key = kdf::expand(&ss, b"aos-wrap", "aos/slot/wrap");
    let cipher = XChaCha20Poly1305::new((&*wrap_key).into());
    let nonce: [u8; 24] = kdf::random_bytes()?;
    let wrapped = cipher
        .encrypt(XNonce::from_slice(&nonce), file_key.as_ref())
        .map_err(|_| OpsecError::Crypto("wrap file_key".into()))?;
    Ok(RecipientSlot {
        eph_x25519_hex: hex::encode(ct.eph_xpk),
        mlkem_ct_hex: hex::encode(ct.mlkem_ct),
        wrap_nonce_hex: hex::encode(nonce),
        wrapped_key_hex: hex::encode(wrapped),
        fingerprint: recipient.fingerprint(),
    })
}

fn unwrap_slot(sec: &kem::XwingSecret, slot: &RecipientSlot) -> Result<Zeroizing<[u8; KEY_LEN]>> {
    let ct = kem::XwingCiphertext {
        mlkem_ct: hex::decode(&slot.mlkem_ct_hex)
            .map_err(|_| OpsecError::Header("mlkem_ct hex".into()))?,
        eph_xpk: hex::decode(&slot.eph_x25519_hex)
            .map_err(|_| OpsecError::Header("eph hex".into()))?
            .try_into()
            .map_err(|_| OpsecError::Header("eph 32o".into()))?,
    };
    let ss = kem::decapsulate(sec, &ct)?;
    let wrap_key = kdf::expand(&ss, b"aos-wrap", "aos/slot/wrap");
    let cipher = XChaCha20Poly1305::new((&*wrap_key).into());
    let nonce: [u8; 24] = hex::decode(&slot.wrap_nonce_hex)
        .map_err(|_| OpsecError::Header("wrap nonce".into()))?
        .try_into()
        .map_err(|_| OpsecError::Header("wrap nonce 24o".into()))?;
    let wrapped =
        hex::decode(&slot.wrapped_key_hex).map_err(|_| OpsecError::Header("wrapped key".into()))?;
    let pt = cipher
        .decrypt(XNonce::from_slice(&nonce), wrapped.as_ref())
        .map_err(|_| OpsecError::Auth)?;
    let arr: [u8; KEY_LEN] = pt
        .try_into()
        .map_err(|_| OpsecError::Header("file_key 32o".into()))?;
    Ok(Zeroizing::new(arr))
}
