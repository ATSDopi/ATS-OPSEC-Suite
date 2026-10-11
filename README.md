# ATS-OPSEC-Suite

**File-centric OPSEC toolkit** — encrypt, hide, transfer and destroy specific
files with surgical granularity, from a cinematic terminal UI.

> ⚠️ **Early stage (v0.1).** The TUI shell, system probe and CLI skeleton are
> functional. The crypto engine is staged for v0.2 — see
> [`docs/SPEC.md`](docs/SPEC.md) for the full design document and roadmap.
> Do **not** rely on it for real secrets yet.

```
 ╔══════════════════════════════════════════════════════════════════════╗
 ║  ATS SECURE BOOTLOADER — integrity check in progress                 ║
 ║                                                                      ║
 ║   █████╗ ████████╗███████╗       ██████╗ ██████╗ ███████╗███████╗   ║
 ║  ██╔══██╗╚══██╔══╝██╔════╝      ██╔═══██╗██╔══██╗██╔════╝██╔════╝   ║
 ║  ███████║   ██║   ███████╗      ██║   ██║██████╔╝███████╗█████╗     ║
 ║  ██╔══██║   ██║   ╚════██║      ██║   ██║██╔═══╝ ╚════██║██╔══╝     ║
 ║  ██║  ██║   ██║   ███████║      ╚██████╔╝██║     ███████║███████╗   ║
 ║  ╚═╝  ╚═╝   ╚═╝   ╚══════╝       ╚═════╝ ╚═╝     ╚══════╝╚══════╝   ║
 ║                                                                      ║
 ║  [ OK ] csprng entropy pool ............. SEEDED 256b                ║
 ║  [ OK ] host capability probe ........... windows · x86_64           ║
 ║  [ OK ] cpu feature matrix .............. AES-NI AVX2 SSE4.2         ║
 ║  [ OK ] secure memory lock .............. VIRTUALLOCK                ║
 ║  [WARN] environment integrity ........... HYPERVISOR PRESENT         ║
 ╚══════════════════════════════════════════════════════════════════════╝
```

## Why this exists

No existing tool combines these pillars in a single interface:

| Tool | Modern crypto | Post-quantum | Stego | Air-gap | TUI |
|---|---|---|---|---|---|
| age / rage | ✅ | ❌ | ❌ | ❌ | ❌ |
| Picocrypt | ✅ | ❌ | ❌ | ❌ | ❌ |
| VeraCrypt | ✅ | ❌ | ❌ | ❌ | ❌ |
| steghide | ❌ | ❌ | ✅ | ❌ | ❌ |
| **ATS-OPSEC-Suite** | cascade + STREAM | hybrid X25519+ML-KEM | dispersed + self-analysis | QR fountain | cyberpunk TUI |

## Quickstart

```powershell
cargo install --path .
ats-opsec            # launch the TUI (boot animation + dashboard)
ats-opsec --no-anim  # skip the boot sequence
ats-opsec probe      # host capability report (real syscalls)
ats-opsec probe --json
```

## TUI

- **Boot sequence** — matrix rain, decoding ASCII logo, module init
  checklist fed by a *real* system probe (CSPRNG, CPUID features,
  hypervisor bit, memory locking, filesystem type, tracer detection).
- **8 keyboard-driven modules** — `←→`/`tab`/`1-8` to navigate:
  DASH (profile + OPSEC score) · VAULT (file picker, encrypt staged) ·
  STEGO · SHRED (passes + honest SSD warnings) · XFER (live QR render) ·
  KEYS · CFG (standard/expert mode, Argon2 params, themes) · LOGS.
- **`p` panic screen** — instant decoy (innocent PowerShell session).
- **`?` help overlay**, `t` theme cycle (cyber/amber/ice/crimson),
  `q`/`ctrl+c` quit.

## CLI

```
ats-opsec probe [--json]     capability report
ats-opsec config show|path   active configuration
ats-opsec encrypt|decrypt|info|shred|stego|qr|bench|keys   [staged v0.2]
```

## Stack

Rust 2024 · `ratatui`+`crossterm` (TUI) · `clap` · `serde`/`toml` ·
`windows-sys`/`libc` (OS probes) · `qrcode` · `blake3`.
Roadmap crates (SPEC §4): `chacha20poly1305`, `aes-gcm`, `serpent`,
`argon2`, `ml-kem`, `ml-dsa`, `raptorq`, `image`, `hound`.

## Commands

| Command | Effect |
|---|---|
| `cargo build` | debug build |
| `cargo build --release` | optimized binary in `target/release/` |
| `cargo test` | unit + render tests (TestBackend) |
| `cargo clippy -- -D warnings` | lint |
| `cargo fmt` | format |

## Security model (honest)

- Secrets in RAM: `zeroize` + `mlock`/`VirtualLock` — **but** swap,
  hibernation and crash dumps can still reach disk.
- File shredding is **not** guaranteed on SSD (TRIM/wear-leveling),
  journaled or CoW filesystems — the UI says so instead of pretending.
- Plausible deniability is a forensic bet, not a legal defense
  (UK RIPA §49, FR art. 434-15-2 compel key disclosure).
- Nothing is "undetectable" — stego is scored with self-analysis, and
  VM/tracer indicators are surfaced as warnings.

## Legal

For legitimate privacy, research and security work only. You are
responsible for complying with your jurisdiction's laws on encryption,
steganography and data destruction.

## License

MIT — see [LICENSE](LICENSE).
