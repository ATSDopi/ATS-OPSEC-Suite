//! Générateur de passphrases diceware + évaluation zxcvbn.
//! Wordlist EFF large embarquée (~7772 mots ≈ 12,9 bits/mot).

use crate::error::{OpsecError, Result};

static WORDLIST: &str = include_str!("../../assets/wordlist.txt");

fn words() -> Vec<&'static str> {
    WORDLIST
        .lines()
        .map(str::trim)
        .filter(|w| !w.is_empty())
        .collect()
}

/// Entropie théorique d'une passphrase diceware de `n` mots : n·log2(|list|).
pub fn diceware_bits(n: usize) -> f64 {
    n as f64 * (words().len() as f64).log2()
}

/// Taille de la wordlist embarquée.
pub fn wordlist_len() -> usize {
    words().len()
}

/// Passphrase diceware : `n` mots tirés au CSPRNG, joints par `sep`.
/// Entropie ≈ n × 12,9 bits.
pub fn generate(n: usize, sep: &str) -> Result<String> {
    if !(3..=12).contains(&n) {
        return Err(OpsecError::InvalidParam("3-12 mots".into()));
    }
    let list = words();
    let mut buf = [0u8; 4];
    let mut out = Vec::with_capacity(n);
    for _ in 0..n {
        getrandom::getrandom(&mut buf).map_err(|e| OpsecError::Crypto(format!("rng: {e}")))?;
        // Rejet de biais modulo : on reroll si au-delà de la limite propre.
        let bound = u32::MAX - (u32::MAX % list.len() as u32);
        let mut v = u32::from_le_bytes(buf);
        while v >= bound {
            getrandom::getrandom(&mut buf).map_err(|e| OpsecError::Crypto(format!("rng: {e}")))?;
            v = u32::from_le_bytes(buf);
        }
        out.push(list[(v as usize) % list.len()]);
    }
    Ok(out.join(sep))
}

/// Score zxcvbn 0-4 + estimation grossière en bits (pour le meter TUI).
pub fn strength(pw: &str) -> (u8, f64) {
    if pw.is_empty() {
        return (0, 0.0);
    }
    let est = zxcvbn::zxcvbn(pw, &[]);
    let score = est.score() as u8;
    let bits = (est.guesses() as f64).log2().min(128.0);
    (score, bits)
}
