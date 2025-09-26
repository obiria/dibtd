use crate::{
    errors::{DIBTDError, Result},
    types::*,
    utils::{lagrange_coefficient, scalar_add, scalar_mul},
};
use secp256k1::{PublicKey, Scalar, Secp256k1, SecretKey};
use std::collections::HashMap;

pub struct DKGProtocol {
    pub participants: HashMap<usize, DKGParticipant>,
    pub n: usize,
    pub t: usize,
}

impl DKGProtocol {
    pub fn new(n: usize, t: usize) -> Result<Self> {
        if t > n || t == 0 {
            return Err(DIBTDError::InvalidThreshold(t, n));
        }

        Ok(Self {
            participants: HashMap::new(),
            n,
            t,
        })
    }

    /// Initialize a participant in the DKG protocol
    pub fn init_participant(&mut self, index: usize) -> Result<()> {
        if index == 0 || index > self.n {
            return Err(DIBTDError::DKGProtocolFailed(
                "Invalid participant index".to_string(),
            ));
        }

        let f_0 = Polynomial::new(self.t - 1);
        let f_1 = Polynomial::new(self.t - 1);

        let secp = Secp256k1::new();
        let mut commitments_0 = Vec::new();
        let mut commitments_1 = Vec::new();

        for i in 1..=self.n {
            let share_0 = f_0.evaluate(i);
            let share_1 = f_1.evaluate(i);

            // Convert scalars to secret keys for public key generation
            let sk_0 = SecretKey::from_slice(&share_0.to_be_bytes())?;
            let sk_1 = SecretKey::from_slice(&share_1.to_be_bytes())?;

            let comm_0 = PublicKey::from_secret_key(&secp, &sk_0);
            let comm_1 = PublicKey::from_secret_key(&secp, &sk_1);

            commitments_0.push(comm_0);
            commitments_1.push(comm_1);
        }

        let participant = DKGParticipant {
            index,
            f_0,
            f_1,
            commitments_0,
            commitments_1,
            shares_received: HashMap::new(),
        };

        self.participants.insert(index, participant);
        Ok(())
    }

    /// Generate and distribute shares from one participant to all others
    pub fn distribute_shares(&self, from: usize) -> Result<HashMap<usize, (Scalar, Scalar)>> {
        let participant = self
            .participants
            .get(&from)
            .ok_or_else(|| DIBTDError::DKGProtocolFailed("Participant not found".to_string()))?;

        let mut shares = HashMap::new();

        for to in 1..=self.n {
            if to != from {
                let share_0 = participant.f_0.evaluate(to);
                let share_1 = participant.f_1.evaluate(to);
                shares.insert(to, (share_0, share_1));
            }
        }

        Ok(shares)
    }

    /// Receive shares at a participant
    pub fn receive_shares(
        &mut self,
        to: usize,
        from: usize,
        shares: (Scalar, Scalar),
    ) -> Result<()> {
        let participant = self
            .participants
            .get_mut(&to)
            .ok_or_else(|| DIBTDError::DKGProtocolFailed("Participant not found".to_string()))?;

        participant.shares_received.insert(from, shares);
        Ok(())
    }

    /// Verify received shares
    pub fn verify_shares(&self, participant_index: usize) -> Result<bool> {
        let participant = self
            .participants
            .get(&participant_index)
            .ok_or_else(|| DIBTDError::DKGProtocolFailed("Participant not found".to_string()))?;

        let secp = Secp256k1::new();

        for (&from, &(share_0, share_1)) in &participant.shares_received {
            let sender = self
                .participants
                .get(&from)
                .ok_or_else(|| DIBTDError::DKGProtocolFailed("Sender not found".to_string()))?;

            // Convert scalars to secret keys for public key generation
            let sk_0 = SecretKey::from_slice(&share_0.to_be_bytes())?;
            let sk_1 = SecretKey::from_slice(&share_1.to_be_bytes())?;

            let expected_0 = PublicKey::from_secret_key(&secp, &sk_0);
            let expected_1 = PublicKey::from_secret_key(&secp, &sk_1);

            if sender.commitments_0[participant_index - 1] != expected_0
                || sender.commitments_1[participant_index - 1] != expected_1
            {
                return Ok(false);
            }
        }

        Ok(true)
    }

    /// Compute the final master keys after all shares are received and verified
    pub fn finalize(&self) -> Result<(MasterPublicKey, HashMap<usize, MasterSecretShare>)> {
        if self.participants.len() < self.t {
            return Err(DIBTDError::InsufficientShares(
                self.participants.len(),
                self.t,
            ));
        }

        let secp = Secp256k1::new();
        let mut secret_shares = HashMap::new();

        // Compute aggregated shares for each participant
        for (&index, participant) in &self.participants {
            // Each participant's share is the sum of:
            // 1. Their own polynomial evaluated at their index
            // 2. All shares received from others (which are their polynomials evaluated at this index)
            let mut s_i = participant.f_0.evaluate(index); // Own contribution
            let mut z_i = participant.f_1.evaluate(index); // Own contribution

            for (&_from, &(share_0, share_1)) in &participant.shares_received {
                s_i = scalar_add(&s_i, &share_0);
                z_i = scalar_add(&z_i, &share_1);
            }

            secret_shares.insert(index, MasterSecretShare { index, s_i, z_i });
        }

        // Compute master public key using Lagrange interpolation
        let indices: Vec<usize> = (1..=self.t).collect();
        let mut y: Option<PublicKey> = None;
        let mut gamma: Option<PublicKey> = None;

        for &i in &indices {
            let share = secret_shares
                .get(&i)
                .ok_or_else(|| DIBTDError::DKGProtocolFailed("Missing share".to_string()))?;

            let coeff = lagrange_coefficient(&indices, i, 0)?;

            let s_i_scaled = scalar_mul(&share.s_i, &coeff);
            let z_i_scaled = scalar_mul(&share.z_i, &coeff);

            let sk_y = SecretKey::from_slice(&s_i_scaled.to_be_bytes())?;
            let sk_gamma = SecretKey::from_slice(&z_i_scaled.to_be_bytes())?;

            let y_i = PublicKey::from_secret_key(&secp, &sk_y);
            let gamma_i = PublicKey::from_secret_key(&secp, &sk_gamma);

            y = Some(match y {
                None => y_i,
                Some(acc) => acc.combine(&y_i)?,
            });

            gamma = Some(match gamma {
                None => gamma_i,
                Some(acc) => acc.combine(&gamma_i)?,
            });
        }

        let mpk = MasterPublicKey {
            y: y.unwrap(),
            gamma: gamma.unwrap(),
            params: SystemParams {
                n: self.n,
                t: self.t,
            },
        };

        Ok((mpk, secret_shares))
    }
}

/// Generate distributed private keys for a group
pub fn distributed_keygen(
    master_shares: &HashMap<usize, MasterSecretShare>,
    group_id: &GroupIdentity,
    threshold: usize,
) -> Result<HashMap<usize, PrivateKeyShare>> {
    let mut private_shares = HashMap::new();
    let secp = Secp256k1::new();

    // Compute H1(group_id)
    let id_hash = crate::utils::hash_h1(group_id.id.as_bytes());

    // Each DKGC node i has shares s_i and z_i
    // For the group, they compute ψ_i = s_i + H1(id) * z_i
    // These ψ_i values are already valid Shamir shares of the group secret

    // Collect ψ_i values from threshold DKGC nodes
    let mut group_shares = Vec::new();
    for (index, share) in master_shares.iter().take(threshold) {
        let id_z = scalar_mul(&id_hash, &share.z_i);
        let psi = scalar_add(&share.s_i, &id_z);
        group_shares.push((*index, psi));
    }

    // Now we need to create shares for group members
    // The group_shares are (t,n)-threshold shares from DKGC
    // We need to create (group_threshold, group_members)-threshold shares for the group

    // First, reconstruct the group secret using Lagrange interpolation
    let indices: Vec<usize> = group_shares.iter().map(|(i, _)| *i).collect();
    let mut group_secret = Scalar::ZERO;

    for (index, share) in &group_shares {
        let coeff = crate::utils::lagrange_coefficient(&indices, *index, 0)?;
        let weighted = scalar_mul(share, &coeff);
        group_secret = scalar_add(&group_secret, &weighted);
    }

    // Create a new polynomial with the group secret as constant term
    let poly = Polynomial::with_constant(group_id.threshold - 1, group_secret);

    // Generate shares for each group member
    for member_index in 1..=group_id.members {
        let psi_i = poly.evaluate(member_index);

        let sk = SecretKey::from_slice(&psi_i.to_be_bytes())?;
        let verification_key = PublicKey::from_secret_key(&secp, &sk);

        private_shares.insert(
            member_index,
            PrivateKeyShare {
                index: member_index,
                psi_i,
                verification_key,
            },
        );
    }

    Ok(private_shares)
}
