use crate::{
    errors::{DIBTDError, Result},
    types::*,
    utils::{lagrange_coefficient, scalar_add, scalar_mul},
};
use secp256k1::{PublicKey, Scalar, Secp256k1};
use std::collections::HashMap;

pub struct ThresholdOperations;

impl ThresholdOperations {
    /// Reconstruct a secret from shares using Lagrange interpolation
    pub fn reconstruct_secret(
        shares: &[(usize, Scalar)],
        threshold: usize,
    ) -> Result<Scalar> {
        if shares.len() < threshold {
            return Err(DIBTDError::InsufficientShares(shares.len(), threshold));
        }
        
        let indices: Vec<usize> = shares.iter().map(|(i, _)| *i).collect();
        let mut result = Scalar::ZERO;
        
        for &(index, ref share) in shares.iter().take(threshold) {
            let coeff = lagrange_coefficient(&indices[..threshold], index, 0)?;
            let weighted = scalar_mul(share, &coeff);
            result = scalar_add(&result, &weighted);
        }
        
        Ok(result)
    }
    
    /// Reconstruct a public key from shares
    pub fn reconstruct_public_key(
        shares: &[(usize, PublicKey)],
        threshold: usize,
    ) -> Result<PublicKey> {
        if shares.len() < threshold {
            return Err(DIBTDError::InsufficientShares(shares.len(), threshold));
        }
        
        let secp = Secp256k1::new();
        let indices: Vec<usize> = shares.iter().map(|(i, _)| *i).collect();
        let mut result: Option<PublicKey> = None;
        
        for &(index, ref share) in shares.iter().take(threshold) {
            let coeff = lagrange_coefficient(&indices[..threshold], index, 0)?;
            let weighted = share.mul_tweak(&secp, &coeff)?;
            
            result = Some(match result {
                None => weighted,
                Some(acc) => acc.combine(&weighted)?,
            });
        }
        
        result.ok_or(DIBTDError::DecryptionFailed)
    }
    
    /// Verify threshold consistency for a set of shares
    pub fn verify_threshold_consistency(
        shares: &HashMap<usize, PrivateKeyShare>,
        _mpk: &MasterPublicKey,
        _group_id: &str,
        threshold: usize,
    ) -> Result<bool> {
        if shares.len() < threshold {
            return Ok(false);
        }
        
        // Threshold consistency means that any threshold subset of shares
        // can reconstruct to the same secret. We verify this by checking
        // that the shares form a valid threshold sharing scheme.
        
        // Take two different subsets and verify they would reconstruct to the same value
        let indices: Vec<usize> = shares.keys().copied().collect();
        
        if indices.len() < threshold + 1 {
            // With only threshold shares, we can't verify consistency
            // but we assume it's valid if we have exactly threshold shares
            return Ok(indices.len() == threshold);
        }
        
        // Get first threshold subset
        let subset1: Vec<(usize, Scalar)> = indices[..threshold]
            .iter()
            .map(|&i| (i, shares[&i].psi_i))
            .collect();
        
        // Get second threshold subset (with one different share)
        let mut subset2_indices = indices[1..threshold].to_vec();
        subset2_indices.push(indices[threshold]);
        let subset2: Vec<(usize, Scalar)> = subset2_indices
            .iter()
            .map(|&i| (i, shares[&i].psi_i))
            .collect();
        
        // Reconstruct secrets from both subsets
        let secret1 = Self::reconstruct_secret(&subset1, threshold)?;
        let secret2 = Self::reconstruct_secret(&subset2, threshold)?;
        
        // They should be equal for valid threshold sharing
        Ok(secret1 == secret2)
    }
}