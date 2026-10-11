use thiserror::Error;

#[derive(Error, Debug)]
pub enum OpsecError {
    #[error("I/O : {0}")]
    Io(#[from] std::io::Error),

    #[error("en-tête invalide : {0}")]
    Header(String),

    #[error("format non reconnu (pas un container .aos)")]
    BadMagic,

    #[error("authentification échouée — mot de passe incorrect ou données corrompues")]
    Auth,

    #[error("cryptographie : {0}")]
    Crypto(String),

    #[error("mot de passe requis (prompt interactif impossible ; utiliser OPSEC_PASSWORD)")]
    PasswordRequired,

    #[error("paramètre invalide : {0}")]
    InvalidParam(String),

    #[error("opération annulée")]
    Cancelled,
}

pub type Result<T> = std::result::Result<T, OpsecError>;
