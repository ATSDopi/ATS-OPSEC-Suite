# ATS-OPSEC-Suite

**File-centric OPSEC toolkit** — encrypt, hide, transfer and destroy specific
files with surgical granularity, from a cinematic terminal UI.

> ⚠️ **v0.2 — crypto engine live but unaudited.** The `.aos` container format,
> streaming AEAD, Argon2id KDF, hybrid post-quantum KEM (X-Wing:
> X25519+ML-KEM-768), keyring and shredding are implemented and tested
> (26 tests). This is **not** a security-audited codebase — design rationale in
> [`docs/SPEC.md`](docs/SPEC.md). Use for real secrets at your own risk.

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

# encryption
ats-opsec encrypt secrets.zip                    # → secrets.zip.aos (argon2id)
ats-opsec encrypt big.iso --cipher cascade       # xchacha20 + aes-256-gcm
ats-opsec encrypt notes.txt --compress --pad     # zstd + size padding
ats-opsec decrypt secrets.zip.aos                # → secrets.zip
ats-opsec info secrets.zip.aos                   # audit container header

# hybrid post-quantum recipients (X-Wing: x25519 + ml-kem-768)
ats-opsec keys gen alice                         # → %APPDATA%/ats-opsec/keys/
ats-opsec encrypt report.pdf --to @alice         # no password needed
ats-opsec decrypt report.pdf.aos --key alice

ats-opsec keys passphrase -n 7                   # diceware (~90 bits)
ats-opsec shred secrets.zip -p 3                 # best-effort secure erase
ats-opsec bench                                  # argon2 calib + aead speed
```

## TUI

- **Boot sequence** — matrix rain, decoding ASCII logo, module init
  checklist fed by a *real* system probe (CSPRNG, CPUID features,
  hypervisor bit, memory locking, filesystem type, tracer detection).
- **6 keyboard-driven modules** — `←→`/`tab`/`1-6` to navigate:
  DASH (host profile, OPSEC score, prefs, local time) ·
  CRYPT (encrypt/decrypt/audit — passphrase *or* recipients mode) ·
  STEGO · SHRED (real multi-pass overwrite) · KEYS (X-Wing keyring) ·
  LOGS.
- **Drag & drop** — drop a file onto the terminal on CRYPT or SHRED
  and it becomes the target. `j` jumps to any path, `h` goes home,
  `backspace` climbs up, drive letters appear at the filesystem root.
- **Input modals** — masked passphrase entry with live zxcvbn strength
  meter; long ops run in background workers with progress.
- **`p` panic screen** — instant decoy (innocent PowerShell session).
- **`?` help overlay**, `t` theme cycle (cyber/amber/ice/crimson),
  `q`/`ctrl+c` quit.

## Keys vs passwords — the two ways to lock a file

Every encryption needs a key. Where it comes from defines two modes:

**Passphrase mode** (symmetric) — your passphrase *is* the key, stretched
through Argon2id (~1.6 s, 64 MiB — brute-force gets expensive fast).
Use it for **your own files**, or when you can whisper the secret to
the recipient.

**Recipient mode** (asymmetric, post-quantum) — each keyring entry is an
X-Wing pair: a **public key** (an open padlock you hand out — anyone can
lock a file for you, nobody can open it) and a **secret key** (yours
alone, the only thing that unlocks). To send a file without sharing any
password:

```
you:    ats-opsec keys pub alice → give alice the .pub file / hex
alice:  ats-opsec encrypt report.pdf --to alice   # locks to YOUR padlock
you:    ats-opsec decrypt report.pdf.aos --key alice   # only YOUR sec key opens it
```

X-Wing combines X25519 + ML-KEM-768 (FIPS 203): safe even if one half is
broken — including by future quantum computers (protects against
"harvest now, decrypt later" collection of today's ciphertext).

## `.aos` container (v1)

```
"AOS1" | header_len u32 | header JSON | chunk stream | random padding?
chunk := u32 LE (bit31 = LAST) | ciphertext (plaintext + 16B AEAD tag)
```

- **KDF**: Argon2id (64 MiB / t3 / p4 default; up to 2 GiB in expert mode)
  + HKDF-SHA256 subkeys — header salt + params stored, authenticated.
- **AEAD**: XChaCha20-Poly1305 (default), AES-256-GCM (AES-NI) or
  **cascade** (XChaCha inside AES-GCM). Per-chunk counter nonces +
  random 16B nonce prefix; header bound via AAD (tamper-proof metadata).
- **STREAM**: chunked (256 KiB default) — wrong password fails on the
  first chunk, truncation is detected, multi-GB files don't touch RAM.
- **Recipients**: X-Wing hybrid KEM (X25519 + ML-KEM-768 per
  draft-irtf-cfrg-xwing) — secure even if one half breaks; multi-recipient
  slots wrap a random 32B file key.
- **Options**: keyfiles (BLAKE3 mixed), Zstandard pre-encryption,
  4 KiB-quantized + jittered size padding, shred-original.
- **Measured** (Ryzen-class, release): ~1.1 GiB/s per AEAD layer,
  ~0.63 GiB/s cascade. Argon2id 64 MiB ≈ 1.6 s.

## CLI

```
ats-opsec encrypt <file> [--cipher xchacha20|aes256gcm|cascade]
                         [--to @name | --to-pub hex] [--keyfile f]
                         [--compress] [--pad] [--shred] [-m/-t/-p argon2]
ats-opsec decrypt <file.aos> [--key name] [--keyfile f] [-o out]
ats-opsec info <file.aos> [--json]    container audit
ats-opsec shred <file> [-p N]         N-pass overwrite + rename + unlink
ats-opsec keys gen|list|pub|export|import|delete|passphrase
ats-opsec bench [--argon-only|--aead-only] [--mib N]
ats-opsec stego|qr                     staged (v0.3)
ats-opsec probe [--json] · config show|path
```

## Stack

Rust 2024 · `ratatui`+`crossterm` (TUI) · `clap` · `serde`/`toml` ·
`windows-sys`/`libc` (OS probes) · `qrcode` · `blake3` · `argon2` ·
`hkdf`/`sha2`/`sha3` · `chacha20poly1305` + `aes-gcm` · `ml-kem` (FIPS 203)
+ `x25519-dalek` · `zstd` · `zeroize` + `subtle` · `zxcvbn` · `getrandom`.

Roadmap crates (SPEC §4): `ml-dsa`, `serpent`, `raptorq`, `image`, `hound`,
`sssa`, `entropy`.

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
