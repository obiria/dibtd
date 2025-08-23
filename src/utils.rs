use secp256k1::{Scalar, PublicKey, SecretKey, Secp256k1};
use sha2::{Sha256, Digest};
use crate::errors::Result;
use crate::types::Proof;
use num_bigint::{BigUint, BigInt};
use num_traits::{One, Zero};
use rand::rngs::OsRng;

/// Compute Lagrange coefficient for threshold cryptography
pub fn lagrange_coefficient(indices: &[usize], i: usize, j: usize) -> Result<Scalar> {
    let mut num = BigUint::one();
    let mut den = BigUint::one();
    
    let q = BigUint::from_bytes_be(&[
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFE,
        0xBA, 0xAE, 0xDC, 0xE6, 0xAF, 0x48, 0xA0, 0x3B,
        0xBF, 0xD2, 0x5E, 0x8C, 0xD0, 0x36, 0x41, 0x41,
    ]);
    
    for &k in indices {
        if k != i {
            let k_big = BigUint::from(k);
            let i_big = BigUint::from(i);
            let j_big = BigUint::from(j);
            
            // numerator: (j - k) mod q
            let num_factor = if j >= k {
                (j_big.clone() - k_big.clone()) % &q
            } else {
                &q - ((k_big.clone() - j_big.clone()) % &q)
            };
            num = (num * num_factor) % &q;
            
            // denominator: (i - k) mod q
            let den_factor = if i >= k {
                (i_big.clone() - k_big) % &q
            } else {
                &q - ((k_big - i_big) % &q)
            };
            
            den = (den * den_factor) % &q;
        }
    }
    
    // Compute den^(-1) mod q
    let den_inv = mod_inverse(&den, &q)?;
    let result = (num * den_inv) % &q;
    
    let bytes = result.to_bytes_be();
    let mut scalar_bytes = [0u8; 32];
    let offset = 32_usize.saturating_sub(bytes.len());
    scalar_bytes[offset..].copy_from_slice(&bytes);
    
    Ok(Scalar::from_be_bytes(scalar_bytes).unwrap())
}

fn mod_inverse(a: &BigUint, m: &BigUint) -> Result<BigUint> {
    let a_int = BigInt::from(a.clone());
    let m_int = BigInt::from(m.clone());
    
    let (gcd, x, _) = extended_gcd_signed(&a_int, &m_int);
    
    if gcd != BigInt::one() {
        return Err(crate::errors::DIBTDError::InvalidThreshold(0, 0));
    }
    
    // Ensure x is positive
    let result = ((x % &m_int) + &m_int) % &m_int;
    
    // Convert back to BigUint (we know it's positive now)
    Ok(result.to_biguint().unwrap())
}

fn extended_gcd_signed(a: &BigInt, b: &BigInt) -> (BigInt, BigInt, BigInt) {
    if a.is_zero() {
        return (b.clone(), BigInt::zero(), BigInt::one());
    }
    
    let (gcd, x1, y1) = extended_gcd_signed(&(b % a), a);
    let x = y1.clone() - (b / a) * x1.clone();
    let y = x1;
    
    (gcd, x, y)
}

/// Hash function H1: {0,1}* -> Z_q
pub fn hash_h1(data: &[u8]) -> Scalar {
    let mut hasher = Sha256::new();
    hasher.update(b"H1:");
    hasher.update(data);
    let hash = hasher.finalize();
    Scalar::from_be_bytes(hash.into()).unwrap()
}

/// Hash function H2: G -> {0,1}^ρ
pub fn hash_h2(point: &PublicKey) -> Vec<u8> {
    let mut hasher = Sha256::new();
    hasher.update(b"H2:");
    hasher.update(&point.serialize());
    hasher.finalize().to_vec()
}

/// Hash function H2 for arbitrary bytes: {0,1}* -> {0,1}^ρ
pub fn hash_h2_bytes(data: &[u8]) -> Vec<u8> {
    let mut hasher = Sha256::new();
    hasher.update(b"H2:");
    hasher.update(data);
    hasher.finalize().to_vec()
}

/// Hash function H3: G×G×G -> Z_q
pub fn hash_h3(p1: &PublicKey, p2: &PublicKey, data: &[u8]) -> Scalar {
    let mut hasher = Sha256::new();
    hasher.update(b"H3:");
    hasher.update(&p1.serialize());
    hasher.update(&p2.serialize());
    hasher.update(data);
    let hash = hasher.finalize();
    Scalar::from_be_bytes(hash.into()).unwrap()
}

/// Compute a Schnorr signature for proof of knowledge
pub fn schnorr_prove(secret: &Scalar, context: &str) -> Result<Proof> {
    let secp = Secp256k1::new();
    let k = Scalar::random_custom(&mut OsRng);
    
    // Convert k to secret key for commitment
    let k_key = SecretKey::from_slice(&k.to_be_bytes()).unwrap();
    let r = PublicKey::from_secret_key(&secp, &k_key);
    
    let mut hasher = Sha256::new();
    hasher.update(context.as_bytes());
    hasher.update(&r.serialize());
    let c = Scalar::from_be_bytes(hasher.finalize().into()).unwrap();
    
    // Scalar arithmetic: mu = k + secret * c
    let secret_c = scalar_mul(secret, &c);
    let mu = scalar_add(&k, &secret_c);
    
    Ok(Proof { r, mu })
}

/// Verify a Schnorr signature
pub fn schnorr_verify(proof: &Proof, public_key: &PublicKey, context: &str) -> bool {
    let secp = Secp256k1::new();
    
    let mut hasher = Sha256::new();
    hasher.update(context.as_bytes());
    hasher.update(&proof.r.serialize());
    let c = Scalar::from_be_bytes(hasher.finalize().into()).unwrap();
    
    // Convert mu to secret key to get mu*G
    let mu_key = SecretKey::from_slice(&proof.mu.to_be_bytes()).unwrap();
    let mu_point = PublicKey::from_secret_key(&secp, &mu_key);
    
    // Compute c*public_key
    let c_pk = public_key.mul_tweak(&secp, &c).unwrap();
    
    // Compute r + c*public_key
    let rhs = proof.r.combine(&c_pk).unwrap();
    
    // Verify: mu*G = r + c*public_key
    mu_point == rhs
}

/// XOR operation for byte arrays
pub fn xor_bytes(a: &[u8], b: &[u8]) -> Vec<u8> {
    a.iter().zip(b.iter()).map(|(x, y)| x ^ y).collect()
}

/// Pad or truncate bytes to specified length
pub fn pad_or_truncate(data: &[u8], len: usize) -> Vec<u8> {
    let mut result = vec![0u8; len];
    let copy_len = data.len().min(len);
    result[..copy_len].copy_from_slice(&data[..copy_len]);
    result
}

// Helper functions for scalar arithmetic
pub fn scalar_add(a: &Scalar, b: &Scalar) -> Scalar {
    let a_bytes = a.to_be_bytes();
    let b_bytes = b.to_be_bytes();
    
    // Perform addition modulo the curve order
    let a_big = BigUint::from_bytes_be(&a_bytes);
    let b_big = BigUint::from_bytes_be(&b_bytes);
    let q = BigUint::from_bytes_be(&[
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFE,
        0xBA, 0xAE, 0xDC, 0xE6, 0xAF, 0x48, 0xA0, 0x3B,
        0xBF, 0xD2, 0x5E, 0x8C, 0xD0, 0x36, 0x41, 0x41,
    ]);
    
    let sum = (a_big + b_big) % q;
    let bytes = sum.to_bytes_be();
    let mut result_bytes = [0u8; 32];
    let offset = 32_usize.saturating_sub(bytes.len());
    result_bytes[offset..].copy_from_slice(&bytes);
    
    Scalar::from_be_bytes(result_bytes).unwrap()
}

pub fn scalar_mul(a: &Scalar, b: &Scalar) -> Scalar {
    let a_bytes = a.to_be_bytes();
    let b_bytes = b.to_be_bytes();
    
    let a_big = BigUint::from_bytes_be(&a_bytes);
    let b_big = BigUint::from_bytes_be(&b_bytes);
    let q = BigUint::from_bytes_be(&[
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFE,
        0xBA, 0xAE, 0xDC, 0xE6, 0xAF, 0x48, 0xA0, 0x3B,
        0xBF, 0xD2, 0x5E, 0x8C, 0xD0, 0x36, 0x41, 0x41,
    ]);
    
    let product = (a_big * b_big) % q;
    let bytes = product.to_bytes_be();
    let mut result_bytes = [0u8; 32];
    let offset = 32_usize.saturating_sub(bytes.len());
    result_bytes[offset..].copy_from_slice(&bytes);
    
    Scalar::from_be_bytes(result_bytes).unwrap()
}

pub fn scalar_negate(a: &Scalar) -> Scalar {
    let a_bytes = a.to_be_bytes();
    let a_big = BigUint::from_bytes_be(&a_bytes);
    let q = BigUint::from_bytes_be(&[
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFE,
        0xBA, 0xAE, 0xDC, 0xE6, 0xAF, 0x48, 0xA0, 0x3B,
        0xBF, 0xD2, 0x5E, 0x8C, 0xD0, 0x36, 0x41, 0x41,
    ]);
    
    let neg = if a_big.is_zero() {
        BigUint::zero()
    } else {
        q - a_big
    };
    
    let bytes = neg.to_bytes_be();
    let mut result_bytes = [0u8; 32];
    let offset = 32_usize.saturating_sub(bytes.len());
    result_bytes[offset..].copy_from_slice(&bytes);
    
    Scalar::from_be_bytes(result_bytes).unwrap()
}

pub fn scalar_from_u32(value: u32) -> Scalar {
    let mut bytes = [0u8; 32];
    bytes[28..32].copy_from_slice(&value.to_be_bytes());
    Scalar::from_be_bytes(bytes).unwrap()
}