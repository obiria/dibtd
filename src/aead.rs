use aes_gcm::{
    aead::{Aead, AeadCore, KeyInit, OsRng},
    Aes256Gcm, Key, Nonce,
};
use crate::errors::{DIBTDError, Result};

pub struct AEADCipher;

impl AEADCipher {
    /// Generate a new AEAD key
    pub fn generate_key() -> [u8; 32] {
        let key = Aes256Gcm::generate_key(OsRng);
        let mut key_bytes = [0u8; 32];
        key_bytes.copy_from_slice(&key);
        key_bytes
    }
    
    /// Generate a new nonce
    pub fn generate_nonce() -> [u8; 12] {
        let nonce = Aes256Gcm::generate_nonce(&mut OsRng);
        let mut nonce_bytes = [0u8; 12];
        nonce_bytes.copy_from_slice(&nonce);
        nonce_bytes
    }
    
    /// Encrypt data with AEAD
    pub fn encrypt(
        key: &[u8; 32],
        nonce: &[u8; 12],
        plaintext: &[u8],
        associated_data: &[u8],
    ) -> Result<Vec<u8>> {
        let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(key));
        let nonce = Nonce::from_slice(nonce);
        
        cipher
            .encrypt(nonce, aes_gcm::aead::Payload {
                msg: plaintext,
                aad: associated_data,
            })
            .map_err(|e| DIBTDError::AEADError(e.to_string()))
    }
    
    /// Decrypt data with AEAD
    pub fn decrypt(
        key: &[u8; 32],
        nonce: &[u8; 12],
        ciphertext: &[u8],
        associated_data: &[u8],
    ) -> Result<Vec<u8>> {
        let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(key));
        let nonce = Nonce::from_slice(nonce);
        
        cipher
            .decrypt(nonce, aes_gcm::aead::Payload {
                msg: ciphertext,
                aad: associated_data,
            })
            .map_err(|e| DIBTDError::AEADError(e.to_string()))
    }
    
    /// Pack key, nonce, and tag into a single message for DIBTD encryption
    pub fn pack_aead_params(key: &[u8; 32], nonce: &[u8; 12], tag: &[u8; 16]) -> Vec<u8> {
        let mut packed = Vec::with_capacity(32 + 12 + 16);
        packed.extend_from_slice(key);
        packed.extend_from_slice(nonce);
        packed.extend_from_slice(tag);
        packed
    }
    
    /// Unpack AEAD parameters from decrypted message
    pub fn unpack_aead_params(data: &[u8]) -> Result<([u8; 32], [u8; 12], [u8; 16])> {
        if data.len() != 60 {
            return Err(DIBTDError::AEADError("Invalid packed data length".to_string()));
        }
        
        let mut key = [0u8; 32];
        let mut nonce = [0u8; 12];
        let mut tag = [0u8; 16];
        
        key.copy_from_slice(&data[0..32]);
        nonce.copy_from_slice(&data[32..44]);
        tag.copy_from_slice(&data[44..60]);
        
        Ok((key, nonce, tag))
    }
}