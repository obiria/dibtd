#[cfg(test)]
mod tests {
    use dibtd_ephr::*;
    use std::collections::HashMap;

    fn setup_test_system(
        n: usize,
        t: usize,
    ) -> Result<(MasterPublicKey, HashMap<usize, MasterSecretShare>)> {
        let mut dkg = dkg::DKGProtocol::new(n, t)?;

        for i in 1..=n {
            dkg.init_participant(i)?;
        }

        let mut all_shares = HashMap::new();
        for from in 1..=n {
            let shares = dkg.distribute_shares(from)?;
            all_shares.insert(from, shares);
        }

        for to in 1..=n {
            for (from, shares_map) in &all_shares {
                if let Some(share) = shares_map.get(&to) {
                    dkg.receive_shares(to, *from, *share)?;
                }
            }
        }

        for i in 1..=n {
            assert!(dkg.verify_shares(i)?);
        }

        dkg.finalize()
    }

    #[test]
    fn test_full_system_flow() {
        // Setup parameters
        let n = 5;
        let t = 3;
        let group_members = 4;
        let group_threshold = 2;

        // Setup DKG system
        let (mpk, master_shares) = setup_test_system(n, t).expect("DKG setup failed");

        // Create group identity
        let group_id = GroupIdentity {
            id: "test_group".to_string(),
            threshold: group_threshold,
            members: group_members,
        };

        // Generate private keys for group
        let private_shares = dkg::distributed_keygen(&master_shares, &group_id, t)
            .expect("Distributed keygen failed");
        assert_eq!(private_shares.len(), group_members);

        // Test message
        let message = b"Test medical record data";

        // Encrypt
        let ciphertext = encryption::DIBTDEncryption::encrypt(message, &group_id.id, &mpk)
            .expect("Encryption failed");

        // Generate decryption shares
        let mut decryption_shares = Vec::new();
        for i in 1..=group_threshold {
            if let Some(private_share) = private_shares.get(&i) {
                let dec_share =
                    encryption::DIBTDEncryption::share_decrypt(&ciphertext, private_share)
                        .expect("Share decryption failed");
                decryption_shares.push(dec_share);
            }
        }

        // Decrypt
        let decrypted =
            encryption::DIBTDEncryption::decrypt(&ciphertext, &decryption_shares, group_threshold)
                .expect("Decryption failed");

        assert_eq!(message.to_vec(), decrypted);
    }

    #[test]
    fn test_insufficient_shares_fails() {
        let n = 5;
        let t = 3;
        let group_threshold = 3;

        let (mpk, master_shares) = setup_test_system(n, t).expect("DKG setup failed");

        let group_id = GroupIdentity {
            id: "test_group".to_string(),
            threshold: group_threshold,
            members: 4,
        };

        let private_shares = dkg::distributed_keygen(&master_shares, &group_id, t)
            .expect("Distributed keygen failed");

        let message = b"Test data";
        let ciphertext = encryption::DIBTDEncryption::encrypt(message, &group_id.id, &mpk)
            .expect("Encryption failed");

        // Generate only 2 shares (need 3)
        let mut decryption_shares = Vec::new();
        for i in 1..=2 {
            if let Some(private_share) = private_shares.get(&i) {
                let dec_share =
                    encryption::DIBTDEncryption::share_decrypt(&ciphertext, private_share)
                        .expect("Share decryption failed");
                decryption_shares.push(dec_share);
            }
        }

        // Should fail with insufficient shares
        let result =
            encryption::DIBTDEncryption::decrypt(&ciphertext, &decryption_shares, group_threshold);

        assert!(matches!(result, Err(DIBTDError::InsufficientShares(2, 3))));
    }

    #[test]
    fn test_aead_integration() {
        let n = 3;
        let t = 2;

        let (mpk, master_shares) = setup_test_system(n, t).expect("DKG setup failed");

        let group_id = GroupIdentity {
            id: "test_group".to_string(),
            threshold: 2,
            members: 3,
        };

        let private_shares = dkg::distributed_keygen(&master_shares, &group_id, t)
            .expect("Distributed keygen failed");

        // Large medical data
        let ehr_data = b"Patient: Jane Doe\n\
                         Medical Record Number: 123456\n\
                         Date: 2024-01-15\n\
                         Chief Complaint: Annual checkup\n\
                         Vital Signs:\n\
                         - Blood Pressure: 118/76 mmHg\n\
                         - Heart Rate: 68 bpm\n\
                         - Temperature: 98.6 degree F\n\
                         - Respiratory Rate: 16/min\n\
                         Lab Results:\n\
                         - Glucose: 92 mg/dL\n\
                         - Cholesterol: 180 mg/dL\n\
                         - HDL: 55 mg/dL\n\
                         - LDL: 110 mg/dL\n\
                         Assessment: Patient in good health";

        // Encrypt with AEAD
        let aead_key = aead::AEADCipher::generate_key();
        let nonce = aead::AEADCipher::generate_nonce();
        let associated_data = b"Medical Record 2024";

        let encrypted_ehr = aead::AEADCipher::encrypt(&aead_key, &nonce, ehr_data, associated_data)
            .expect("AEAD encryption failed");

        // Extract tag
        let tag_start = encrypted_ehr.len().saturating_sub(16);
        let mut tag = [0u8; 16];
        tag.copy_from_slice(&encrypted_ehr[tag_start..]);

        // Pack and encrypt with DIBTD
        let packed_params = aead::AEADCipher::pack_aead_params(&aead_key, &nonce, &tag);
        let ciphertext = encryption::DIBTDEncryption::encrypt(&packed_params, &group_id.id, &mpk)
            .expect("DIBTD encryption failed");

        // Generate decryption shares
        let mut decryption_shares = Vec::new();
        for i in 1..=2 {
            if let Some(private_share) = private_shares.get(&i) {
                let dec_share =
                    encryption::DIBTDEncryption::share_decrypt(&ciphertext, private_share)
                        .expect("Share decryption failed");
                decryption_shares.push(dec_share);
            }
        }

        // Decrypt DIBTD
        let decrypted_params =
            encryption::DIBTDEncryption::decrypt(&ciphertext, &decryption_shares, 2)
                .expect("DIBTD decryption failed");

        // Unpack and decrypt AEAD
        let (recovered_key, recovered_nonce, _) =
            aead::AEADCipher::unpack_aead_params(&decrypted_params)
                .expect("Parameter unpacking failed");

        let decrypted_ehr = aead::AEADCipher::decrypt(
            &recovered_key,
            &recovered_nonce,
            &encrypted_ehr,
            associated_data,
        )
        .expect("AEAD decryption failed");

        assert_eq!(ehr_data.to_vec(), decrypted_ehr);
    }

    #[test]
    fn test_proof_verification() {
        let n = 3;
        let t = 2;

        let (mpk, master_shares) = setup_test_system(n, t).expect("DKG setup failed");

        let group_id = GroupIdentity {
            id: "test_group".to_string(),
            threshold: 2,
            members: 3,
        };

        let private_shares = dkg::distributed_keygen(&master_shares, &group_id, t)
            .expect("Distributed keygen failed");

        let message = b"Test";
        let ciphertext = encryption::DIBTDEncryption::encrypt(message, &group_id.id, &mpk)
            .expect("Encryption failed");

        // Generate share and proof
        let private_share = private_shares.get(&1).expect("Private share not found");
        let dec_share = encryption::DIBTDEncryption::share_decrypt(&ciphertext, private_share)
            .expect("Share decryption failed");

        let proof = crypto::ZKProof::prove_share(private_share, &dec_share, "test_context")
            .expect("Proof generation failed");

        // Verify proof
        assert!(crypto::ZKProof::verify_share(
            &proof,
            &private_share.verification_key,
            "test_context",
        ));

        // Should fail with wrong context
        assert!(!crypto::ZKProof::verify_share(
            &proof,
            &private_share.verification_key,
            "wrong_context",
        ));
    }

    #[test]
    fn test_threshold_consistency() {
        let n = 5;
        let t = 3;

        let (mpk, master_shares) = setup_test_system(n, t).expect("DKG setup failed");

        let group_id = GroupIdentity {
            id: "test_group".to_string(),
            threshold: 3,
            members: 5,
        };

        let private_shares = dkg::distributed_keygen(&master_shares, &group_id, t)
            .expect("Distributed keygen failed");

        // Verify threshold consistency
        let is_consistent = threshold::ThresholdOperations::verify_threshold_consistency(
            &private_shares,
            &mpk,
            &group_id.id,
            group_id.threshold,
        )
        .expect("Threshold consistency check failed");

        assert!(is_consistent);
    }

    #[test]
    fn test_different_group_sizes() {
        let n = 5;
        let t = 3;

        let (mpk, master_shares) = setup_test_system(n, t).expect("DKG setup failed");

        // Test different group configurations
        let test_groups = vec![
            (2, 2),  // Minimum case
            (3, 2),  // Standard small group
            (5, 3),  // Medium group
            (10, 6), // Larger group
        ];

        for (members, threshold) in test_groups {
            let group_id = GroupIdentity {
                id: format!("test_group_{}", members),
                threshold,
                members,
            };

            let private_shares = dkg::distributed_keygen(&master_shares, &group_id, t)
                .expect(&format!("Keygen failed for group size {}", members));

            assert_eq!(private_shares.len(), members);

            // Test encryption/decryption works
            let message = b"Test message";
            let ciphertext = encryption::DIBTDEncryption::encrypt(message, &group_id.id, &mpk)
                .expect("Encryption failed");

            // Generate threshold shares
            let mut decryption_shares = Vec::new();
            for i in 1..=threshold {
                if let Some(private_share) = private_shares.get(&i) {
                    let dec_share =
                        encryption::DIBTDEncryption::share_decrypt(&ciphertext, private_share)
                            .expect("Share decryption failed");
                    decryption_shares.push(dec_share);
                }
            }

            let decrypted =
                encryption::DIBTDEncryption::decrypt(&ciphertext, &decryption_shares, threshold)
                    .expect("Decryption failed");

            assert_eq!(message.to_vec(), decrypted);
        }
    }

    #[test]
    fn test_performance_scalability() {
        use std::time::Instant;

        // Test performance doesn't degrade catastrophically with size
        let test_sizes = vec![(3, 2), (5, 3), (7, 4)];
        let mut times = Vec::new();

        for (n, t) in test_sizes {
            let start = Instant::now();
            let _system = setup_test_system(n, t).expect("Setup failed");
            let duration = start.elapsed();
            times.push(duration);

            println!("Setup time for n={}, t={}: {:?}", n, t, duration);
        }

        // Ensure performance is reasonable (less than 10 seconds for largest test)
        assert!(times.iter().all(|&t| t.as_secs() < 10));
    }

    #[test]
    fn test_error_conditions() {
        // Test invalid threshold
        let result = dkg::DKGProtocol::new(5, 6);
        assert!(result.is_err());

        // Test zero threshold
        let result = dkg::DKGProtocol::new(5, 0);
        assert!(result.is_err());

        // Test single node system
        let result = setup_test_system(1, 1);
        assert!(result.is_ok());
    }
}
