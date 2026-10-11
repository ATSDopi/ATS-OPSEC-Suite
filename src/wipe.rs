//! Broyage sécurisé — N passes d'écrasement + fsync + rename aléatoire +
//! truncate + unlink.
//!
//! HONNÊTETÉ FORENSIQUE : sur SSD (TRIM/wear-leveling), FS journalisé ou
//! CoW (btrfs/ZFS/APFS), l'écrasement n'est PAS garanti — le FS et les
//! journaux peuvent conserver les blocs. Le TUI affiche l'avertissement.

use std::fs::{self, File, OpenOptions};
use std::io::{Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};

use crate::error::{OpsecError, Result};

const CHUNK: usize = 1024 * 1024;

#[derive(Debug)]
pub struct ShredReport {
    pub bytes: u64,
    pub passes: u32,
    /// Avertissement contextuel (SSD/CoW/journal) selon le FS détecté.
    pub fs_caveat: Option<String>,
}

#[derive(Debug, Clone, Copy)]
pub enum PassPattern {
    Random,
    Zeros,
    Ones,
}

/// Séquence de passes : [random]×(n-1) puis zeros (dernière passe propre).
fn pattern_for(i: u32, total: u32) -> PassPattern {
    if i == total - 1 {
        PassPattern::Zeros
    } else {
        PassPattern::Random
    }
}

/// Écrase puis supprime `path`. `progress(octets_écrits_au_total)`.
pub fn shred(path: &Path, passes: u32, progress: &mut dyn FnMut(u64)) -> Result<ShredReport> {
    if !path.is_file() {
        return Err(OpsecError::InvalidParam(format!(
            "pas un fichier régulier : {}",
            path.display()
        )));
    }
    let passes = passes.clamp(1, 35);
    let size = fs::metadata(path)?.len();

    {
        let mut f = OpenOptions::new().write(true).open(path)?;
        let mut buf = vec![0u8; CHUNK.min(size as usize).max(1)];
        let mut done = 0u64;
        for i in 0..passes {
            f.seek(SeekFrom::Start(0))?;
            match pattern_for(i, passes) {
                PassPattern::Zeros => buf.fill(0),
                PassPattern::Ones => buf.fill(0xFF),
                PassPattern::Random => getrandom::getrandom(&mut buf)
                    .map_err(|e| OpsecError::Crypto(format!("rng: {e}")))?,
            }
            let mut off = 0u64;
            while off < size {
                let n = ((size - off) as usize).min(buf.len());
                f.write_all(&buf[..n])?;
                off += n as u64;
                done += n as u64;
                progress(done);
            }
            f.sync_data()?;
        }
        f.sync_all()?;
    }

    // Renommages multiples → brouille la table d'allocation / le journal.
    let mut cur = path.to_path_buf();
    let dir = path.parent().unwrap_or_else(|| Path::new("."));
    for _ in 0..3 {
        let mut rnd = [0u8; 8];
        getrandom::getrandom(&mut rnd).map_err(|e| OpsecError::Crypto(format!("rng: {e}")))?;
        let next: PathBuf = dir.join(format!(".{}", hex::encode(rnd)));
        fs::rename(&cur, &next)?;
        cur = next;
    }
    // Truncate à 0 puis taille aléatoire avant suppression.
    {
        let f = File::options().write(true).open(&cur)?;
        f.set_len(0)?;
        let mut rnd = [0u8; 2];
        let _ = getrandom::getrandom(&mut rnd);
        f.set_len((u16::from_le_bytes(rnd) % 4096) as u64)?;
        f.sync_all()?;
    }
    fs::remove_file(&cur)?;

    Ok(ShredReport {
        bytes: size,
        passes,
        fs_caveat: Some(
            "overwrite non garanti sur SSD (TRIM), FS journalisé ou CoW — \
             préférer le chiffrement du volume"
                .into(),
        ),
    })
}
