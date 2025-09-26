use rand::rngs::OsRng;
use secp256k1::{PublicKey, Scalar};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

// Custom serialization for Scalar
mod scalar_serde {
    use super::*;
    use serde::{Deserializer, Serializer};

    pub fn serialize<S>(scalar: &Scalar, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let bytes = scalar.to_be_bytes();
        serializer.serialize_bytes(&bytes)
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Scalar, D::Error>
    where
        D: Deserializer<'de>,
    {
        let bytes: Vec<u8> = Deserialize::deserialize(deserializer)?;
        if bytes.len() != 32 {
            return Err(serde::de::Error::custom("Invalid scalar bytes length"));
        }
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&bytes);
        Scalar::from_be_bytes(arr).map_err(|_| serde::de::Error::custom("Invalid scalar value"))
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MasterPublicKey {
    pub y: PublicKey,
    pub gamma: PublicKey,
    pub params: SystemParams,
}

#[derive(Clone, Debug)]
pub struct MasterSecretShare {
    pub index: usize,
    pub s_i: Scalar,
    pub z_i: Scalar,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SystemParams {
    pub n: usize, // Total participants
    pub t: usize, // Threshold
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Ciphertext {
    pub d: PublicKey,
    pub e: PublicKey,
    pub f: Vec<u8>,
    #[serde(with = "scalar_serde")]
    pub delta: Scalar,
}

#[derive(Clone, Debug)]
pub struct DecryptionShare {
    pub index: usize,
    pub lambda_i: PublicKey,
}

#[derive(Clone, Debug)]
pub struct Proof {
    pub r: PublicKey,
    pub mu: Scalar,
}

#[derive(Clone, Debug)]
pub struct PrivateKeyShare {
    pub index: usize,
    pub psi_i: Scalar,
    pub verification_key: PublicKey,
}

#[derive(Clone, Debug)]
pub struct Polynomial {
    pub coefficients: Vec<Scalar>,
}

impl Polynomial {
    pub fn new(degree: usize) -> Self {
        let mut coefficients = Vec::with_capacity(degree + 1);
        for _ in 0..=degree {
            coefficients.push(Scalar::random_custom(&mut OsRng));
        }
        Self { coefficients }
    }

    pub fn with_constant(degree: usize, constant: Scalar) -> Self {
        let mut coefficients = Vec::with_capacity(degree + 1);
        coefficients.push(constant);
        for _ in 1..=degree {
            coefficients.push(Scalar::random_custom(&mut OsRng));
        }
        Self { coefficients }
    }

    pub fn evaluate(&self, x: usize) -> Scalar {
        use crate::utils::{scalar_add, scalar_from_u32, scalar_mul};

        let mut result = Scalar::ZERO;
        let mut x_power = Scalar::ONE;
        let x_scalar = scalar_from_u32(x as u32);

        for coeff in &self.coefficients {
            let term = scalar_mul(coeff, &x_power);
            result = scalar_add(&result, &term);
            x_power = scalar_mul(&x_power, &x_scalar);
        }
        result
    }
}

#[derive(Clone, Debug)]
pub struct DKGParticipant {
    pub index: usize,
    pub f_0: Polynomial,
    pub f_1: Polynomial,
    pub commitments_0: Vec<PublicKey>,
    pub commitments_1: Vec<PublicKey>,
    pub shares_received: HashMap<usize, (Scalar, Scalar)>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct GroupIdentity {
    pub id: String,
    pub threshold: usize,
    pub members: usize,
}

#[derive(Clone, Debug)]
pub struct AEADPacket {
    pub ciphertext: Vec<u8>,
    pub nonce: [u8; 12],
    pub tag: [u8; 16],
    pub associated_data: Vec<u8>,
}
