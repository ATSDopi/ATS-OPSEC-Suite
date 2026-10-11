//! Implémentations des sous-commandes — stdout = données, stderr = messages.

use std::io::Write;
use std::path::{Path, PathBuf};
use std::time::Instant;

use zeroize::Zeroizing;

use super::{ConfigAction, KeysAction};
use crate::config::Config;
use crate::crypto::engine::{self, Credential, EncryptOptions, KeySource};
use crate::crypto::{Argon2Params, CipherSuite, keys as keystore, passphrase};
use crate::error::{OpsecError, Result};
use crate::sys;
use crate::wipe;

// ---------------------------------------------------------------- utils

/// Mot de passe : `OPSEC_PASSWORD` (scripts/CI) ou prompt masqué.
fn read_password(confirm: bool) -> Result<Zeroizing<Vec<u8>>> {
    if let Ok(p) = std::env::var("OPSEC_PASSWORD")
        && !p.is_empty()
    {
        return Ok(Zeroizing::new(p.into_bytes()));
    }
    let p = rpassword::prompt_password("passphrase: ").map_err(|_| OpsecError::PasswordRequired)?;
    if p.is_empty() {
        return Err(OpsecError::InvalidParam("passphrase vide".into()));
    }
    if confirm {
        let c =
            rpassword::prompt_password("confirm: ").map_err(|_| OpsecError::PasswordRequired)?;
        if p != c {
            return Err(OpsecError::InvalidParam("passphrases différentes".into()));
        }
        let (score, bits) = passphrase::strength(&p);
        if score < 3 {
            eprintln!(
                "[warn] passphrase faible (zxcvbn {score}/4, ~{bits:.0} bits) — `ats-opsec passphrase` pour un diceware"
            );
        }
    }
    Ok(Zeroizing::new(p.into_bytes()))
}

fn load_keyfile(spec: Option<&str>) -> Result<Option<Vec<u8>>> {
    spec.map(|p| std::fs::read(p).map_err(OpsecError::Io))
        .transpose()
}

fn default_out(input: &str, enc: bool) -> PathBuf {
    if enc {
        return PathBuf::from(format!("{input}.aos"));
    }
    let p = Path::new(input);
    if p.extension().and_then(|e| e.to_str()) == Some("aos") {
        p.with_extension("").to_path_buf()
    } else {
        PathBuf::from(format!("{input}.dec"))
    }
}

fn spinner_progress() -> impl FnMut(u64) {
    move |done| {
        eprint!("\r  {:.1} MiB processed", done as f64 / 1048576.0);
    }
}

// ---------------------------------------------------------------- commands

pub fn probe(json: bool) -> Result<()> {
    let p = sys::probe();
    if json {
        println!("{}", serde_json::to_string_pretty(&p).unwrap_or_default());
    } else {
        let yn = |b: Option<bool>| match b {
            Some(true) => "yes",
            Some(false) => "no",
            None => "n/a",
        };
        println!("host         : {} / {}", p.os, p.arch);
        println!(
            "cpu          : aes-ni={} avx2={} sse4.2={}",
            p.cpu.aes_ni, p.cpu.avx2, p.cpu.sse42
        );
        println!("hypervisor   : {}", yn(p.cpu.hypervisor));
        println!(
            "ram          : {} MiB",
            p.total_ram_mb
                .map(|v| v.to_string())
                .unwrap_or_else(|| "n/a".into())
        );
        println!("memlock      : {}", p.memlock.label());
        println!("fs (cwd)     : {}", p.fs_type.as_deref().unwrap_or("n/a"));
        println!("csprng       : {}", if p.rng_ok { "ok" } else { "FAIL" });
        println!("tracer       : {}", yn(p.tracer_detected));
        println!("swap present : {}", yn(p.swap_present));
    }
    Ok(())
}

pub fn config(cfg: &Config, action: ConfigAction) -> Result<()> {
    match action {
        ConfigAction::Show => println!("{}", toml::to_string_pretty(cfg).unwrap_or_default()),
        ConfigAction::Path => match Config::path() {
            Some(p) => println!("{}", p.display()),
            None => println!("config dir unavailable"),
        },
    }
    Ok(())
}

pub struct EncryptArgs {
    pub file: String,
    pub out: Option<String>,
    pub suite: CipherSuite,
    pub recipients: Vec<String>,
    pub keyfile: Option<String>,
    pub compress: bool,
    pub pad: bool,
    pub secure_delete: bool,
    pub config_argon: Argon2Params,
    pub chunk_kib: Option<u32>,
}

pub fn encrypt(a: EncryptArgs) -> Result<()> {
    let input = Path::new(&a.file);
    if !input.is_file() {
        return Err(OpsecError::InvalidParam(format!(
            "fichier introuvable: {}",
            a.file
        )));
    }
    let out = a
        .out
        .map(PathBuf::from)
        .unwrap_or_else(|| default_out(&a.file, true));
    let kf = load_keyfile(a.keyfile.as_deref())?;

    let key_source = if a.recipients.is_empty() {
        KeySource::Password {
            pass: read_password(true)?,
            keyfile: kf,
        }
    } else {
        let pubs: Vec<_> = a
            .recipients
            .iter()
            .map(|r| keystore::load_public(r))
            .collect::<Result<_>>()?;
        eprintln!(
            "[*] recipients: {}",
            pubs.iter()
                .map(|p| p.fingerprint())
                .collect::<Vec<_>>()
                .join(", ")
        );
        KeySource::Recipients(pubs)
    };

    let opts = EncryptOptions {
        suite: a.suite,
        argon2: a.config_argon,
        compress: a.compress,
        pad: a.pad,
        chunk_size: a.chunk_kib.unwrap_or(256) * 1024,
    };

    eprintln!("[*] encrypting → {} ({})", out.display(), a.suite.label());
    let t0 = Instant::now();
    engine::encrypt_file(input, &out, &key_source, &opts, &mut spinner_progress())?;
    eprintln!(
        "\n[ok] {} → {} in {:.1?}",
        a.file,
        out.display(),
        t0.elapsed()
    );

    if a.secure_delete {
        eprintln!("[*] shredding original…");
        wipe::shred(input, 3, &mut |_| {})?;
        eprintln!("[ok] original shredded (caveat: SSD/journal may retain blocks)");
    }
    Ok(())
}

pub fn decrypt(
    file: &str,
    out: Option<&str>,
    key: Option<&str>,
    keyfile: Option<&str>,
    verify: bool,
) -> Result<()> {
    let input = Path::new(file);
    let header = engine::inspect(input)?;
    let kf = load_keyfile(keyfile)?;

    let cred = if header.is_password_mode() {
        Credential::Password {
            pass: read_password(false)?,
            keyfile: kf,
        }
    } else if header.is_recipient_mode() {
        let sec = match key {
            Some(k) => keystore::load_secret(k)?,
            None => try_keyring(&header)?,
        };
        Credential::SecretKey(sec)
    } else {
        return Err(OpsecError::Header("aucun mode d'authentification".into()));
    };

    if verify {
        let mut sink = std::io::sink();
        let mut f = std::fs::File::open(input)?;
        engine::decrypt_stream(&mut f, &mut sink, &cred, &mut spinner_progress())?;
        eprintln!("\n[ok] integrity verified — nothing written");
        return Ok(());
    }

    let out_path = out
        .map(PathBuf::from)
        .unwrap_or_else(|| default_out(file, false));
    eprintln!("[*] decrypting → {}", out_path.display());
    let t0 = Instant::now();
    engine::decrypt_file(input, &out_path, &cred, &mut spinner_progress())?;
    eprintln!(
        "\n[ok] {} → {} in {:.1?}",
        file,
        out_path.display(),
        t0.elapsed()
    );
    Ok(())
}

/// Mode destinataire sans `--key` : essaie chaque `.sec` du keyring.
fn try_keyring(h: &crate::crypto::AosHeader) -> Result<crate::crypto::kem::XwingSecret> {
    for (name, fp, has_sec) in keystore::list()? {
        if !has_sec {
            continue;
        }
        // heuristique : si le fingerprint du destinataire matche, prioriser
        let targeted = h.recipients.iter().any(|s| s.fingerprint == fp);
        if targeted {
            eprintln!("[*] trying keyring key '{name}' ({fp})");
            return keystore::load_secret(&name);
        }
    }
    // sinon brute-try toutes les clés secrètes
    for (name, _, has_sec) in keystore::list()? {
        if has_sec && let Ok(sec) = keystore::load_secret(&name) {
            return Ok(sec);
        }
    }
    Err(OpsecError::InvalidParam(
        "container destinataire — fournir --key @name ou un .sec".into(),
    ))
}

pub fn info(file: &str, json: bool) -> Result<()> {
    let h = engine::inspect(Path::new(file))?;
    if json {
        println!("{}", serde_json::to_string_pretty(&h).unwrap_or_default());
        return Ok(());
    }
    println!("format       : .aos v{}", h.v);
    println!("suite        : {}", h.suite.label());
    println!("chunk size   : {} KiB", h.chunk_size / 1024);
    println!("nonce prefix : {}", h.nonce_prefix_hex);
    println!("compressed   : {}", h.compressed);
    println!("padded       : {}", h.padded);
    match &h.kdf {
        Some(k) => println!(
            "auth         : password ({} m={}KiB t={} p={})",
            k.algo, k.m_kib, k.t, k.p
        ),
        None => println!("auth         : {} recipient slot(s)", h.recipients.len()),
    }
    for (i, s) in h.recipients.iter().enumerate() {
        println!("  slot {i}     : xwing → fingerprint {}", s.fingerprint);
    }
    Ok(())
}

pub fn shred(file: &str, passes: u32, yes: bool) -> Result<()> {
    let path = Path::new(file);
    if !yes {
        eprint!("[?] irreversibly destroy {file} ({passes} passes) ? [y/N] ");
        std::io::stderr().flush().ok();
        let mut l = String::new();
        std::io::stdin().read_line(&mut l).ok();
        if !matches!(l.trim().to_lowercase().as_str(), "y" | "yes") {
            eprintln!("aborted");
            return Ok(());
        }
    }
    let rep = wipe::shred(path, passes, &mut |done| {
        eprint!("\r  {:.1} MiB overwritten", done as f64 / 1048576.0);
    })?;
    eprintln!(
        "\n[ok] shredded {} ({} B, {} passes)",
        file, rep.bytes, rep.passes
    );
    if let Some(c) = rep.fs_caveat {
        eprintln!("[warn] {c}");
    }
    Ok(())
}

pub fn bench() -> Result<()> {
    println!("── argon2id calibration (target ~1s) ──────────────────");
    let mut recommended = Argon2Params::default();
    for m_mib in [64u32, 128, 256, 512, 1024] {
        let p = Argon2Params {
            m_kib: m_mib * 1024,
            t: 3,
            p: 4,
        };
        let salt = crate::crypto::kdf::random_salt()?;
        let material = b"benchmark-material";
        let t0 = Instant::now();
        let _ = crate::crypto::kdf::derive_master(material, &salt, &p)?;
        let d = t0.elapsed();
        println!("  m={:>4} MiB t=3 p=4 → {:>6.0} ms", m_mib, d.as_millis());
        if d.as_millis() <= 1100 {
            recommended = p;
        } else {
            break;
        }
    }
    println!(
        "recommended: -m {} -t {} -p {}",
        recommended.m_kib, recommended.t, recommended.p
    );

    println!("── aead throughput (64 MiB) ───────────────────────────");
    for suite in CipherSuite::ALL {
        let mut out = Vec::new();
        let src = vec![0xABu8; 64 * 1024 * 1024];
        let opts = EncryptOptions {
            suite: *suite,
            argon2: Argon2Params {
                m_kib: 8 * 1024,
                t: 1,
                p: 1,
            },
            ..Default::default()
        };
        let key = KeySource::Recipients(vec![{
            let (_, p) = crate::crypto::kem::keygen()?;
            p
        }]);
        let t0 = Instant::now();
        engine::encrypt_stream(&src[..], &mut out, &key, &opts, &mut |_| {})?;
        let d = t0.elapsed().as_secs_f64();
        println!(
            "  {:<22} {:>6.0} MiB/s ({} chunks)",
            suite.label(),
            64.0 / d,
            (64 * 1024 * 1024) / opts.chunk_size as usize
        );
    }
    Ok(())
}

pub fn keys(action: KeysAction, json: bool) -> Result<()> {
    match action {
        KeysAction::Gen { name } => {
            let (pub_path, sec_path, fp) = keystore::keygen(&name)?;
            println!("[ok] xwing keypair '{name}'");
            println!("     fingerprint : {fp}");
            println!("     public      : {}", pub_path.display());
            println!(
                "     secret      : {}  ⚠ unprotected — store it safe",
                sec_path.display()
            );
        }
        KeysAction::List => {
            let ks = keystore::list()?;
            if json {
                println!("{}", serde_json::to_string_pretty(&ks).unwrap_or_default());
                return Ok(());
            }
            if ks.is_empty() {
                println!("keyring empty — `ats-opsec keys gen <name>`");
            }
            for (n, fp, has_sec) in ks {
                println!(
                    "  {:<20} {}  {}",
                    n,
                    fp,
                    if has_sec { "pub+sec" } else { "pub only" }
                );
            }
        }
        KeysAction::Show { name } => {
            let p = keystore::load_public(&name)?;
            println!("{}", hex::encode(p.to_bytes()));
        }
        KeysAction::Delete { name } => {
            keystore::delete(&name)?;
            println!("[ok] '{name}' deleted from keyring");
        }
    }
    Ok(())
}

pub fn passphrase(words: usize, sep: &str) -> Result<()> {
    let pw = passphrase::generate(words, sep)?;
    let (score, bits) = passphrase::strength(&pw);
    println!("{pw}");
    eprintln!("[zxcvbn {score}/4 · ~{bits:.0} bits entropy]");
    Ok(())
}
