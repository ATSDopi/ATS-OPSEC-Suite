# Security Policy

## Scope

ATS-OPSEC-Suite is a defensive OPSEC tool. If you find a vulnerability in
the code itself (memory safety, crypto misuse, secret leakage, unsafe
defaults), please report it responsibly.

## Reporting

- **Do not** open a public issue for exploitable vulnerabilities.
- Open a private report via GitHub Security Advisories
  (`Security` tab → `Report a vulnerability`), or contact the maintainer
  directly through the profile on https://github.com/ATSDopi.
- Include: affected version/commit, reproduction steps, impact.

## What is NOT a bug

- Shredding being ineffective on SSD/journaled/CoW filesystems — the UI
  and docs disclose this limitation by design (honest forensics).
- Hypervisor/tracer detection being heuristic — it's a warning
  indicator, not a guarantee.
- "Undetectable steganography" claims — none are made; self-analysis
  scoring is planned precisely because detection is possible.

## Cryptography notice

v0.1 ships no encryption engine yet. Post-quantum crates
(`ml-kem`, `ml-dsa`) in the roadmap are **not formally audited** — the
design mandates hybrid X25519+ML-KEM so a break in the PQ half alone
cannot compromise confidentiality.
