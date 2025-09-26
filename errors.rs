use thiserror::Error;

#[derive(Error, Debug)]
pub enum DIBTDError {
    #[error("Invalid threshold parameters: t={0}, n={1}")]
    InvalidThreshold(usize, usize),

    #[error("Insufficient shares for reconstruction: got {0}, need {1}")]
    InsufficientShares(usize, usize),

    #[error("Invalid share verification")]
    InvalidShareVerification,

    #[error("Invalid proof")]
    InvalidProof,

    #[error("Decryption failed")]
    DecryptionFailed,

    #[error("Key generation failed")]
    KeyGenerationFailed,

    #[error("Invalid ciphertext")]
    InvalidCiphertext,

    #[error("Secp256k1 error: {0}")]
    Secp256k1Error(#[from] secp256k1::Error),

    #[error("Serialization error: {0}")]
    SerializationError(String),

    #[error("AEAD error: {0}")]
    AEADError(String),

    #[error("Invalid group identity")]
    InvalidGroupIdentity,

    #[error("DKG protocol failed: {0}")]
    DKGProtocolFailed(String),
}

pub type Result<T> = std::result::Result<T, DIBTDError>;
