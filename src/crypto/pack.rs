//! Multi-fichiers : les entrées (fichiers/dossiers) sont streamées en
//! archive **tar** qui devient le plaintext chiffré du container.
//! Pas de fichier temporaire — `std::io::pipe` branche le tar directement
//! dans le moteur AEAD (RAM constante, rien ne touche le disque en clair).

use std::collections::HashSet;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::thread;

use crate::error::{OpsecError, Result};

/// Écrit `inputs` (fichiers et dossiers) comme archive tar dans `w`.
/// Bloquant — à appeler dans un thread producteur connecté à un pipe.
pub fn write_tar<W: Write>(inputs: &[PathBuf], w: W) -> Result<()> {
    let mut b = tar::Builder::new(w);
    let mut seen: HashSet<String> = HashSet::new();
    for input in inputs {
        let base = input
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_else(|| "root".into());
        let arc = unique_name(&mut seen, &base);
        if input.is_dir() {
            b.append_dir_all(&arc, input)?;
        } else if input.is_file() {
            b.append_path_with_name(input, &arc)?;
        } else {
            return Err(OpsecError::InvalidParam(format!(
                "entrée invalide: {}",
                input.display()
            )));
        }
    }
    b.finish()?;
    Ok(())
}

/// Extrait une archive tar lue depuis `r` vers `dest` (créé si besoin).
/// Bloquant — à appeler dans un thread consommateur connecté à un pipe.
pub fn read_tar<R: Read>(r: R, dest: &Path) -> Result<()> {
    std::fs::create_dir_all(dest)?;
    let mut ar = tar::Archive::new(r);
    ar.unpack(dest)
        .map_err(|e| OpsecError::Crypto(format!("tar unpack: {e}")))?;
    Ok(())
}

/// Paire (reader, writer) OS-backed pour relier deux threads.
pub fn pipe() -> Result<(std::io::PipeReader, std::io::PipeWriter)> {
    std::io::pipe().map_err(|e| OpsecError::Crypto(format!("pipe: {e}")))
}

/// Lance `f` dans un thread et rend son `JoinHandle` (erreur propagée).
pub fn spawn<F>(f: F) -> thread::JoinHandle<Result<()>>
where
    F: FnOnce() -> Result<()> + Send + 'static,
{
    thread::spawn(f)
}

/// Nom d'archive unique : `a`, `a-1`, `a-2`…
fn unique_name(seen: &mut HashSet<String>, base: &str) -> String {
    if seen.insert(base.to_string()) {
        return base.to_string();
    }
    for i in 1u32.. {
        let cand = format!("{base}-{i}");
        if seen.insert(cand.clone()) {
            return cand;
        }
    }
    unreachable!()
}
