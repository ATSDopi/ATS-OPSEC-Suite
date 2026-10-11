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

use aes_gcm::aead::{Aead, KeyInit};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use zeroize::Zeroizing;

use super::ciphers::CipherKind;
use super::format::{self, AosHeader, RecipientSlot};
use super::kdf::{self, KEY_LEN};
use super::{Argon2Params, DEFAULT_CHUNK_SIZE, kem, pack};
use crate::error::{OpsecError, Result};

const TAG_LEN: usize = 16;
const LAST_BIT: u32 = 1 << 31;
const PAD_BLOCK: u64 = 64 * 1024;

// ---------------------------------------------------------------- options

#[derive(Debug, Clone)]
pub struct EncryptOptions {
    /// Couches AEAD ordonnées (interne → externe). >1 = cascade.
    pub ciphers: Vec<CipherKind>,
    pub argon2: Argon2Params,
    pub compress: bool,
    pub pad: bool,
    /// Le contenu clair est une archive tar (multi-fichiers) — interne.
    pub packed: bool,
    pub chunk_size: u32,
}

impl Default for EncryptOptions {
    fn default() -> Self {
        Self {
            ciphers: vec![CipherKind::XChaCha20],
            argon2: Argon2Params::default(),
            compress: false,
            pad: false,
            packed: false,
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
    let mut header = AosHeader::new(&opts.ciphers, opts.chunk_size, nonce_prefix);
    header.compressed = opts.compress;
    header.padded = opts.pad;
    header.packed = opts.packed;

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

    let layers = Layers::new(&opts.ciphers, &master, &nonce_prefix)?;

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

    let layers = Layers::new(&header.cipher_kinds()?, &master, &nonce_prefix)?;

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
        // chaque couche ajoute son tag 16o (+ marge)
        let max_ct = header.chunk_size as usize + TAG_LEN * layers.len() + 8;
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

/// Chiffre plusieurs entrées (fichiers/dossiers) → un seul `.aos` contenant
/// une archive tar streamée via pipe (header `packed=true`, rien de temporaire
/// en clair sur disque).
pub fn encrypt_paths(
    inputs: &[PathBuf],
    output: &Path,
    key: &KeySource,
    opts: &EncryptOptions,
    progress: &mut dyn FnMut(u64),
) -> Result<PathBuf> {
    if inputs.is_empty() {
        return Err(OpsecError::InvalidParam("aucune entrée".into()));
    }
    // Cas trivial : un seul fichier régulier → stream direct.
    if inputs.len() == 1 && inputs[0].is_file() {
        let mut o = opts.clone();
        o.packed = false;
        return encrypt_file(&inputs[0], output, key, &o, progress);
    }
    for i in inputs {
        if !i.exists() {
            return Err(OpsecError::InvalidParam(format!(
                "entrée introuvable: {}",
                i.display()
            )));
        }
    }
    let mut o = opts.clone();
    o.packed = true;
    let (reader, writer) = pack::pipe()?;
    let owned = inputs.to_vec();
    let tar_thread = pack::spawn(move || pack::write_tar(&owned, writer));
    let tmp = tmp_name(output, "aos.tmp");
    {
        let dst = BufWriter::new(File::create(&tmp)?);
        encrypt_stream(reader, dst, key, &o, progress).inspect_err(|_| {
            let _ = fs::remove_file(&tmp);
        })?;
    }
    tar_thread
        .join()
        .map_err(|_| OpsecError::Crypto("tar thread panic".into()))??;
    fs::rename(&tmp, output)?;
    Ok(output.to_path_buf())
}

/// Déchiffre un `.aos` → sortie via tmp + rename (vérifier avant d'écrire).
/// Container `packed` : `output` est traité comme un DOSSIER — extraction
/// dans `<output>.tmp` puis rename atomique (aucun artefact partiel).
pub fn decrypt_file(
    input: &Path,
    output: &Path,
    cred: &Credential,
    progress: &mut dyn FnMut(u64),
) -> Result<PathBuf> {
    if inspect(input).map(|h| h.packed).unwrap_or(false) {
        return decrypt_packed(input, output, cred, progress);
    }
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

/// Déchiffre un container packed (tar) → dossier `output`.
fn decrypt_packed(
    input: &Path,
    output: &Path,
    cred: &Credential,
    progress: &mut dyn FnMut(u64),
) -> Result<PathBuf> {
    let (reader, writer) = pack::pipe()?;
    let tmp_dir = tmp_name(output, "unp.tmp");
    let dest = tmp_dir.clone();
    let tar_thread = pack::spawn(move || pack::read_tar(reader, &dest));
    let src = File::open(input)?;
    decrypt_stream(src, writer, cred, progress).inspect_err(|_| {
        let _ = fs::remove_dir_all(&tmp_dir);
    })?;
    tar_thread
        .join()
        .map_err(|_| OpsecError::Crypto("untar thread panic".into()))?
        .inspect_err(|_| {
            let _ = fs::remove_dir_all(&tmp_dir);
        })?;
    if output.exists() {
        return Err(OpsecError::InvalidParam(format!(
            "destination existe: {}",
            output.display()
        )));
    }
    fs::rename(&tmp_dir, output)?;
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

/// Pile de couches AEAD — l'ordre du `Vec` est l'ordre de scellement.
struct Layers(Vec<super::ciphers::LayerImpl>);

impl Layers {
    fn new(
        kinds: &[CipherKind],
        master: &Zeroizing<[u8; KEY_LEN]>,
        prefix: &[u8; 16],
    ) -> Result<Self> {
        if kinds.is_empty() {
            return Err(OpsecError::InvalidParam("aucun cipher sélectionné".into()));
        }
        Ok(Self(
            kinds
                .iter()
                .enumerate()
                .map(|(i, k)| k.make_layer(master, prefix, i))
                .collect(),
        ))
    }

    fn len(&self) -> usize {
        self.0.len()
    }

    /// Scelle : couche 0 sur le clair, couche n-1 la plus externe.
    fn seal(&self, counter: u64, pt: &[u8], aad: &[u8]) -> Result<Vec<u8>> {
        let mut ct = pt.to_vec();
        for l in &self.0 {
            let kind_nonce_len = l_nonce_len(l);
            ct = l.seal(
                &nonce_of(counter, kind_nonce_len)[..kind_nonce_len],
                &ct,
                aad,
            )?;
        }
        Ok(ct)
    }

    /// Ouvre : couche externe d'abord, interne en dernier.
    fn open(&self, counter: u64, ct: &[u8], aad: &[u8]) -> Result<Vec<u8>> {
        let mut pt = ct.to_vec();
        for l in self.0.iter().rev() {
            let kind_nonce_len = l_nonce_len(l);
            pt = l.open(
                &nonce_of(counter, kind_nonce_len)[..kind_nonce_len],
                &pt,
                aad,
            )?;
        }
        Ok(pt)
    }
}

/// Taille de nonce d'une couche instanciée (pour le découpage compteur).
fn l_nonce_len(l: &super::ciphers::LayerImpl) -> usize {
    use super::ciphers::LayerImpl as L;
    match l {
        L::XChaCha(_) => 24,
        L::Aes256Gcm(_) | L::Aes128Gcm(_) | L::GcmSiv(_) => 12,
        L::Eax(_) | L::Ascon(_) => 16,
        L::Deoxys(_) => 15,
        L::Aegis(_) => 32,
    }
}

/// Nonce pour la couche : compteur u64 BE dans les 8 derniers octets,
/// zéros avant, tronqué à `len`. Unicité garantie : chaque clé de couche
/// est HKDF-saltée au nonce_prefix aléatoire → (clé, nonce) jamais réutilisée.
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
