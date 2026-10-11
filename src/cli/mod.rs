//! Sous-commandes CLI — parité avec le TUI. En v0.1 : `probe`, `config`
//! et le lanceur TUI sont réels ; le reste est stubé proprement (v0.2+).

use crate::config::Config;
use crate::error::Result;
use crate::sys;
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
    /// Encrypt a file into an .aos container. [staged v0.2]
    Encrypt { file: String },
    /// Decrypt an .aos container. [staged v0.2]
    Decrypt { file: String },
    /// Dump an .aos container header. [staged v0.2]
    Info { file: String },
    /// Securely shred a file. [staged v0.2]
    Shred { file: String },
    /// Steganography operations. [staged v0.2]
    Stego { file: String },
    /// Air-gap QR transfer. [staged v0.2]
    Qr { file: String },
    /// Calibrate Argon2id parameters for this machine. [staged v0.2]
    Bench,
    /// Key management (keygen, keyring, export). [staged v0.2]
    Keys,
}

#[derive(Subcommand)]
pub enum ConfigAction {
    /// Print the active configuration.
    Show,
    /// Print the config file path.
    Path,
}

pub fn dispatch(cli: Cli, config: &mut Config) -> Result<()> {
    match cli.command {
        None | Some(Command::Tui) => crate::tui::run(config, cli.no_anim),
        Some(Command::Probe) => {
            let p = sys::probe();
            if cli.json {
                println!("{}", serde_json::to_string_pretty(&p).unwrap_or_default());
            } else {
                print_probe(&p);
            }
            Ok(())
        }
        Some(Command::Config {
            action: ConfigAction::Show,
        }) => {
            println!("{}", toml::to_string_pretty(config).unwrap_or_default());
            Ok(())
        }
        Some(Command::Config {
            action: ConfigAction::Path,
        }) => {
            match Config::path() {
                Some(p) => println!("{}", p.display()),
                None => println!("config dir unavailable"),
            }
            Ok(())
        }
        Some(other) => {
            let name = match other {
                Command::Encrypt { .. } => ("encrypt", "v0.2"),
                Command::Decrypt { .. } => ("decrypt", "v0.2"),
                Command::Info { .. } => ("info", "v0.2"),
                Command::Shred { .. } => ("shred", "v0.2"),
                Command::Stego { .. } => ("stego", "v0.2"),
                Command::Qr { .. } => ("qr", "v0.2"),
                Command::Bench => ("bench", "v0.2"),
                Command::Keys => ("keys", "v0.2"),
                _ => unreachable!(),
            };
            eprintln!(
                "[staged] `{}` is planned for {} — see docs/SPEC.md roadmap",
                name.0, name.1
            );
            Ok(())
        }
    }
}

fn print_probe(p: &sys::SystemProfile) {
    let yes_no = |b: Option<bool>| match b {
        Some(true) => "yes",
        Some(false) => "no",
        None => "n/a",
    };
    println!("host         : {} / {}", p.os, p.arch);
    println!(
        "cpu          : aes-ni={} avx2={} sse4.2={}",
        p.cpu.aes_ni, p.cpu.avx2, p.cpu.sse42
    );
    println!("hypervisor   : {}", yes_no(p.cpu.hypervisor));
    println!(
        "ram          : {} MiB",
        p.total_ram_mb
            .map(|v| v.to_string())
            .unwrap_or_else(|| "n/a".into())
    );
    println!("memlock      : {}", p.memlock.label());
    println!("fs (cwd)     : {}", p.fs_type.as_deref().unwrap_or("n/a"));
    println!("csprng       : {}", if p.rng_ok { "ok" } else { "FAIL" });
    println!("tracer       : {}", yes_no(p.tracer_detected));
    println!("swap present : {}", yes_no(p.swap_present));
}
