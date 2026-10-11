//! Broyage sécurisé de fichiers — staged v0.1.
//! Implémentation v0.2 : N passes (0x00/0xFF/aléatoire), fsync, rename
//! aléatoire, truncate, unlink + warning FS (SSD/TRIM/journal = non garanti).

/// Rapport d'une opération de shred (v0.2).
#[derive(Debug)]
pub struct ShredReport {
    pub bytes: u64,
    pub passes: u32,
}

pub fn staged_notice() -> &'static str {
    "secure shredder staged for v0.2 — see docs/SPEC.md"
}
