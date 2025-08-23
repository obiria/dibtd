use crate::{
    errors::{DIBTDError, Result},
    types::*,
    utils::{hash_h1, hash_h2, hash_h2_bytes, hash_h3, xor_bytes, pad_or_truncate, 
            scalar_add, scalar_mul},
};
use secp256k1::{PublicKey, Scalar, SecretKey, Secp256k1};
use rand::rngs::OsRng;

pub struct DIBTDEncryption;

impl DIBTDEncryption {
    /// Encrypt a message for a group identity
    pub fn encrypt(
        message: &[u8],
        group_id: &str,
        mpk: &MasterPublicKey,
    ) -> Result<Ciphertext> {
        let secp = Secp256k1::new();
        
        // Select random u
        let u = Scalar::random_custom(&mut OsRng);
        
        // Compute Δ = (Y + H1(id) * Γ) * u
        let id_hash = hash_h1(group_id.as_bytes());
        let gamma_scaled = mpk.gamma.mul_tweak(&secp, &id_hash)?;
        let combined = mpk.y.combine(&gamma_scaled)?;
        let delta = combined.mul_tweak(&secp, &u)?;
        
        // Compute D = u * P
        let u_key = SecretKey::from_slice(&u.to_be_bytes())?;
        let d = PublicKey::from_secret_key(&secp, &u_key);
        
        // Compute r = H1(m, Δ) and E = r * P
        let mut r_input = Vec::new();
        r_input.extend_from_slice(message);
        r_input.extend_from_slice(&delta.serialize());
        let r = hash_h1(&r_input);
        let r_key = SecretKey::from_slice(&r.to_be_bytes())?;
        let e = PublicKey::from_secret_key(&secp, &r_key);
        
        // Compute Θ = H2(Δ)
        let theta = hash_h2(&delta);
        let theta_padded = pad_or_truncate(&theta, message.len());
        
        // Compute Ω = H2(E|Θ)
        let mut omega_input = Vec::new();
        omega_input.extend_from_slice(&e.serialize());
        omega_input.extend_from_slice(&theta);
        let omega = hash_h2_bytes(&omega_input);
        let omega_padded = pad_or_truncate(&omega, message.len());
        
        // Compute X = Θ ⊕ m and F = Ω ⊕ X
        let x = xor_bytes(&theta_padded, message);
        let f = xor_bytes(&omega_padded, &x);
        
        // Calculate δ = u + r * H3(D, E, F)
        let h3_val = hash_h3(&d, &e, &f);
        let r_h3 = scalar_mul(&r, &h3_val);
        let delta_scalar = scalar_add(&u, &r_h3);
        
        Ok(Ciphertext {
            d,
            e,
            f,
            delta: delta_scalar,
        })
    }
    
    /// Generate a decryption share
    pub fn share_decrypt(
        ciphertext: &Ciphertext,
        private_share: &PrivateKeyShare,
    ) -> Result<DecryptionShare> {
        let secp = Secp256k1::new();
        
        // Verify ciphertext integrity: δ * P = D + H3(D, E, F) * E
        let delta_key = SecretKey::from_slice(&ciphertext.delta.to_be_bytes())?;
        let delta_point = PublicKey::from_secret_key(&secp, &delta_key);
        let h3_val = hash_h3(&ciphertext.d, &ciphertext.e, &ciphertext.f);
        let e_scaled = ciphertext.e.mul_tweak(&secp, &h3_val)?;
        let expected = ciphertext.d.combine(&e_scaled)?;
        
        if delta_point != expected {
            return Err(DIBTDError::InvalidCiphertext);
        }
        
        // Compute Λi = Ψi * D
        let lambda_i = ciphertext.d.mul_tweak(&secp, &private_share.psi_i)?;
        
        Ok(DecryptionShare {
            index: private_share.index,
            lambda_i,
        })
    }
    
    /// Combine decryption shares to recover the message
    pub fn decrypt(
        ciphertext: &Ciphertext,
        shares: &[DecryptionShare],
        threshold: usize,
    ) -> Result<Vec<u8>> {
        if shares.len() < threshold {
            return Err(DIBTDError::InsufficientShares(shares.len(), threshold));
        }
        
        let secp = Secp256k1::new();
        let indices: Vec<usize> = shares.iter().map(|s| s.index).collect();
        
        // Compute Δ using Lagrange interpolation
        let mut delta: Option<PublicKey> = None;
        
        for share in shares.iter().take(threshold) {
            let coeff = crate::utils::lagrange_coefficient(&indices[..threshold], share.index, 0)?;
            let weighted = share.lambda_i.mul_tweak(&secp, &coeff)?;
            
            delta = Some(match delta {
                None => weighted,
                Some(acc) => acc.combine(&weighted)?,
            });
        }
        
        let delta = delta.ok_or(DIBTDError::DecryptionFailed)?;
        
        // Compute Θ = H2(Δ)
        let theta = hash_h2(&delta);
        let theta_padded = pad_or_truncate(&theta, ciphertext.f.len());
        
        // Compute Ω = H2(E|Θ)
        let mut omega_input = Vec::new();
        omega_input.extend_from_slice(&ciphertext.e.serialize());
        omega_input.extend_from_slice(&theta);
        let omega = hash_h2_bytes(&omega_input);
        let omega_padded = pad_or_truncate(&omega, ciphertext.f.len());
        
        // Compute m = F ⊕ Θ ⊕ Ω  
        // Since F = Ω ⊕ X and X = Θ ⊕ m
        // We have F = Ω ⊕ Θ ⊕ m
        // Therefore m = F ⊕ Ω ⊕ Θ
        let x = xor_bytes(&ciphertext.f, &omega_padded);
        let message = xor_bytes(&x, &theta_padded);
        
        // Verify: E = H1(m, Δ) * P
        let mut r_input = Vec::new();
        r_input.extend_from_slice(&message);
        r_input.extend_from_slice(&delta.serialize());
        let r = hash_h1(&r_input);
        let r_key = SecretKey::from_slice(&r.to_be_bytes())?;
        let expected_e = PublicKey::from_secret_key(&secp, &r_key);
        
        if expected_e != ciphertext.e {
            return Err(DIBTDError::DecryptionFailed);
        }
        
        Ok(message)
    }
}