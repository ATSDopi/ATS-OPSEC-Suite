//! Sous-commandes CLI — parité avec le TUI.

mod cmds;

use crate::config::Config;
use crate::crypto::CipherSuite;
use crate::error::Result;
use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(
    name = "ats-opsec",
    version,
    about = "ATS-OPSEC-Suite — file-centric OPSEC toolkit (crypto, stego, air-gap, anti-forensics)",
    long_about = None
)]
pub struct Cli {
    /// Skip the boot animation.
    #[arg(long, global = true)]
    pub no_anim: bool,

    /// Machine-readable output where supported.
    #[arg(long, global = true)]
    pub json: bool,

    #[command(subcommand)]
    pub command: Option<Command>,
}

#[derive(Subcommand)]
pub enum Command {
    /// Launch the TUI (default when no subcommand is given).
    Tui,

    /// Probe host security capabilities and print the report.
    Probe,

    /// Show or edit configuration.
    Config {
        #[command(subcommand)]
        action: ConfigAction,
    },

    /// Encrypt a file into an .aos container.
    Encrypt {
        /// Input file.
        file: String,
        /// Output path (default: <file>.aos).
        #[arg(short, long)]
        out: Option<String>,
        /// Cipher suite: xchacha20 | aes256gcm | cascade.
        #[arg(long, default_value = "xchacha20", value_parser = parse_suite)]
        cipher: CipherSuite,
        /// Recipient(s): keyring name (@alice) or .pub file path.
        /// When set, no password is needed (X-Wing hybrid KEM).
        #[arg(long = "to")]
        recipients: Vec<String>,
        /// Extra keyfile hashed into the password material (BLAKE3).
        #[arg(long)]
        keyfile: Option<String>,
        /// Compress with zstd before encrypting.
        #[arg(long)]
        compress: bool,
        /// Pad output size to hide the real plaintext length.
        #[arg(long)]
        pad: bool,
        /// Securely shred the original file after a verified encrypt.
        #[arg(long)]
        secure_delete: bool,
        /// Argon2 memory (KiB).
        #[arg(short = 'm', long)]
        argon_mem: Option<u32>,
        /// Argon2 iterations.
        #[arg(short = 't', long)]
        argon_time: Option<u32>,
        /// Argon2 lanes.
        #[arg(short = 'p', long)]
        argon_lanes: Option<u32>,
        /// Chunk size in KiB (default 256).
        #[arg(long)]
        chunk_kib: Option<u32>,
    },

    /// Decrypt an .aos container (verify-then-write: plaintext only
    /// touches disk after the AEAD tags check out).
    Decrypt {
        /// .aos input file.
        file: String,
        /// Output path (default: strip .aos or <file>.dec).
        #[arg(short, long)]
        out: Option<String>,
        /// Secret key for recipient mode: keyring name (@alice) or .sec path.
        #[arg(long)]
        key: Option<String>,
        /// Keyfile used at encryption time.
        #[arg(long)]
        keyfile: Option<String>,
        /// Verify integrity only — writes nothing.
        #[arg(long)]
        verify: bool,
    },

    /// Dump an .aos container header (no key needed).
    Info { file: String },

    /// Securely shred a file (N passes + rename + truncate + unlink).
    /// Honest warning: not guaranteed on SSD/journaled/CoW filesystems.
    Shred {
        file: String,
        #[arg(long, default_value = "3")]
        passes: u32,
        /// Skip the confirmation prompt.
        #[arg(short = 'y', long)]
        yes: bool,
    },

    /// Steganography operations. [staged v0.3]
    Stego { file: String },

    /// Air-gap QR transfer. [fountain animated TX staged v0.3]
    Qr { file: String },

    /// Calibrate Argon2id for this machine (~1s target) + AEAD throughput.
    Bench,

    /// Key management (hybrid X-Wing X25519+ML-KEM-768 pairs).
    Keys {
        #[command(subcommand)]
        action: KeysAction,
    },

    /// Generate a diceware passphrase (EFF large wordlist).
    Passphrase {
        /// Number of words (3-12, default 6 ≈ 77 bits).
        #[arg(short, long, default_value = "6")]
        words: usize,
        /// Word separator.
        #[arg(short, long, default_value = "-")]
        sep: String,
    },
}

#[derive(Subcommand)]
pub enum ConfigAction {
    Show,
    Path,
}

#[derive(Subcommand)]
pub enum KeysAction {
    /// Generate an X-Wing keypair (X25519 + ML-KEM-768).
    Gen { name: String },
    /// List keyring entries.
    List,
    /// Print a public key (hex) for sharing.
    Show { name: String },
    /// Delete a keypair from the keyring.
    Delete { name: String },
}

fn parse_suite(s: &str) -> std::result::Result<CipherSuite, String> {
    CipherSuite::parse(s)
        .ok_or_else(|| format!("unknown suite '{s}' — xchacha20 | aes256gcm | cascade"))
}

pub fn dispatch(cli: Cli, config: &mut Config) -> Result<()> {
    match cli.command {
        None | Some(Command::Tui) => crate::tui::run(config, cli.no_anim),
        Some(Command::Probe) => cmds::probe(cli.json),
        Some(Command::Config { action }) => cmds::config(config, action),
        Some(Command::Encrypt {
            file,
            out,
            cipher,
            recipients,
            keyfile,
            compress,
            pad,
            secure_delete,
            argon_mem,
            argon_time,
            argon_lanes,
            chunk_kib,
        }) => cmds::encrypt(cmds::EncryptArgs {
            file,
            out,
            suite: cipher,
            recipients,
            keyfile,
            compress,
            pad,
            secure_delete,
            config_argon: argon_merge(config, argon_mem, argon_time, argon_lanes),
            chunk_kib,
        }),
        Some(Command::Decrypt {
            file,
            out,
            key,
            keyfile,
            verify,
        }) => cmds::decrypt(
            &file,
            out.as_deref(),
            key.as_deref(),
            keyfile.as_deref(),
            verify,
        ),
        Some(Command::Info { file }) => cmds::info(&file, cli.json),
        Some(Command::Shred { file, passes, yes }) => cmds::shred(&file, passes, yes),
        Some(Command::Bench) => cmds::bench(),
        Some(Command::Keys { action }) => cmds::keys(action, cli.json),
        Some(Command::Passphrase { words, sep }) => cmds::passphrase(words, &sep),
        Some(Command::Stego { .. }) => staged("stego", "v0.3"),
        Some(Command::Qr { .. }) => staged("qr", "v0.3"),
    }
}

fn argon_merge(
    config: &Config,
    m: Option<u32>,
    t: Option<u32>,
    p: Option<u32>,
) -> crate::crypto::Argon2Params {
    let mut a = config.argon2;
    if let Some(v) = m {
        a.m_kib = v;
    }
    if let Some(v) = t {
        a.t = v;
    }
    if let Some(v) = p {
        a.p = v;
    }
    a.clamp();
    a
}

fn staged(name: &str, version: &str) -> Result<()> {
    eprintln!("[staged] `{name}` is planned for {version} — see docs/SPEC.md roadmap");
    Ok(())
}
