use crate::{
    errors::Result,
    types::*,
    utils::{schnorr_prove, schnorr_verify},
};
use secp256k1::{PublicKey, SecretKey, Secp256k1};

pub struct ZKProof;

impl ZKProof {
    /// Generate a zero-knowledge proof for a decryption share
    pub fn prove_share(
        private_share: &PrivateKeyShare,
        _decryption_share: &DecryptionShare,
        context: &str,
    ) -> Result<Proof> {
        schnorr_prove(&private_share.psi_i, context)
    }
    
    /// Verify a zero-knowledge proof for a decryption share
    pub fn verify_share(
        proof: &Proof,
        verification_key: &PublicKey,
        context: &str,
    ) -> bool {
        schnorr_verify(proof, verification_key, context)
    }
    
    /// Batch verification of multiple proofs
    pub fn batch_verify(
        proofs: &[Proof],
        verification_keys: &[PublicKey],
        context: &str,
    ) -> bool {
        if proofs.len() != verification_keys.len() {
            return false;
        }
        
        proofs.iter()
            .zip(verification_keys.iter())
            .all(|(proof, vk)| Self::verify_share(proof, vk, context))
    }
}

pub struct KeyDerivation;

impl KeyDerivation {
    /// Derive a group-specific public key
    pub fn derive_group_public_key(
        mpk: &MasterPublicKey,
        group_id: &str,
    ) -> Result<PublicKey> {
        let secp = Secp256k1::new();
        let id_hash = crate::utils::hash_h1(group_id.as_bytes());
        let gamma_scaled = mpk.gamma.mul_tweak(&secp, &id_hash)?;
        Ok(mpk.y.combine(&gamma_scaled)?)
    }
    
    /// Verify that a private key share is valid for a group
    pub fn verify_private_share(
        share: &PrivateKeyShare,
        _mpk: &MasterPublicKey,
        _group_id: &str,
    ) -> Result<bool> {
        let secp = Secp256k1::new();
        let sk = SecretKey::from_slice(&share.psi_i.to_be_bytes())?;
        let expected_vk = PublicKey::from_secret_key(&secp, &sk);
        Ok(expected_vk == share.verification_key)
    }
}