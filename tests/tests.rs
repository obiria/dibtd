use dibtd_ephr::*;
use std::collections::HashMap;

#[test]
fn test_full_system_flow() {
    // Setup parameters
    let n = 5;
    let t = 3;
    let group_members = 4;
    let group_threshold = 2;
    
    // Initialize DKG
    let mut dkg = dkg::DKGProtocol::new(n, t).unwrap();
    
    // Initialize participants
    for i in 1..=n {
        dkg.init_participant(i).unwrap();
    }
    
    // Distribute shares
    let mut all_shares = HashMap::new();
    for from in 1..=n {
        let shares = dkg.distribute_shares(from).unwrap();
        all_shares.insert(from, shares);
    }
    
    // Receive shares
    for to in 1..=n {
        for (from, shares_map) in &all_shares {
            if let Some(share) = shares_map.get(&to) {
                dkg.receive_shares(to, *from, *share).unwrap();
            }
        }
    }
    
    // Verify shares
    for i in 1..=n {
        assert!(dkg.verify_shares(i).unwrap());
    }
    
    // Finalize DKG
    let (mpk, master_shares) = dkg.finalize().unwrap();
    
    // Create group identity
    let group_id = GroupIdentity {
        id: "test_group".to_string(),
        threshold: group_threshold,
        members: group_members,
    };
    
    // Generate private keys for group
    let private_shares = dkg::distributed_keygen(&master_shares, &group_id, t).unwrap();
    assert_eq!(private_shares.len(), group_members);
    
    // Test message
    let message = b"Test medical record data";
    
    // Encrypt
    let ciphertext = encryption::DIBTDEncryption::encrypt(
        message,
        &group_id.id,
        &mpk,
    ).unwrap();
    
    // Generate decryption shares
    let mut decryption_shares = Vec::new();
    for i in 1..=group_threshold {
        if let Some(private_share) = private_shares.get(&i) {
            let dec_share = encryption::DIBTDEncryption::share_decrypt(
                &ciphertext,
                private_share,
            ).unwrap();
            decryption_shares.push(dec_share);
        }
    }
    
    // Decrypt
    let decrypted = encryption::DIBTDEncryption::decrypt(
        &ciphertext,
        &decryption_shares,
        group_threshold,
    ).unwrap();
    
    assert_eq!(message.to_vec(), decrypted);
}

#[test]
fn test_insufficient_shares_fails() {
    // Setup system
    let n = 5;
    let t = 3;
    let group_threshold = 3;
    
    let mut dkg = dkg::DKGProtocol::new(n, t).unwrap();
    for i in 1..=n {
        dkg.init_participant(i).unwrap();
    }
    
    let mut all_shares = HashMap::new();
    for from in 1..=n {
        let shares = dkg.distribute_shares(from).unwrap();
        all_shares.insert(from, shares);
    }
    
    for to in 1..=n {
        for (from, shares_map) in &all_shares {
            if let Some(share) = shares_map.get(&to) {
                dkg.receive_shares(to, *from, *share).unwrap();
            }
        }
    }
    
    let (mpk, master_shares) = dkg.finalize().unwrap();
    
    let group_id = GroupIdentity {
        id: "test_group".to_string(),
        threshold: group_threshold,
        members: 4,
    };
    
    let private_shares = dkg::distributed_keygen(&master_shares, &group_id, t).unwrap();
    
    let message = b"Test data";
    let ciphertext = encryption::DIBTDEncryption::encrypt(
        message,
        &group_id.id,
        &mpk,
    ).unwrap();
    
    // Generate only 2 shares (need 3)
    let mut decryption_shares = Vec::new();
    for i in 1..=2 {
        if let Some(private_share) = private_shares.get(&i) {
            let dec_share = encryption::DIBTDEncryption::share_decrypt(
                &ciphertext,
                private_share,
            ).unwrap();
            decryption_shares.push(dec_share);
        }
    }
    
    // Should fail with insufficient shares
    let result = encryption::DIBTDEncryption::decrypt(
        &ciphertext,
        &decryption_shares,
        group_threshold,
    );
    
    assert!(matches!(result, Err(DIBTDError::InsufficientShares(2, 3))));
}

#[test]
fn test_aead_integration() {
    // Setup system
    let n = 3;
    let t = 2;
    
    let mut dkg = dkg::DKGProtocol::new(n, t).unwrap();
    for i in 1..=n {
        dkg.init_participant(i).unwrap();
    }
    
    let mut all_shares = HashMap::new();
    for from in 1..=n {
        let shares = dkg.distribute_shares(from).unwrap();
        all_shares.insert(from, shares);
    }
    
    for to in 1..=n {
        for (from, shares_map) in &all_shares {
            if let Some(share) = shares_map.get(&to) {
                dkg.receive_shares(to, *from, *share).unwrap();
            }
        }
    }
    
    let (mpk, master_shares) = dkg.finalize().unwrap();
    
    let group_id = GroupIdentity {
        id: "test_group".to_string(),
        threshold: 2,
        members: 3,
    };
    
    let private_shares = dkg::distributed_keygen(&master_shares, &group_id, t).unwrap();
    
    // Large medical data - Fixed: escaped the degree symbol
    let ehr_data = b"Patient: Jane Doe\n\
                     Medical Record Number: 123456\n\
                     Date: 2024-01-15\n\
                     Chief Complaint: Annual checkup\n\
                     Vital Signs:\n\
                     - Blood Pressure: 118/76 mmHg\n\
                     - Heart Rate: 68 bpm\n\
                     - Temperature: 98.6\xB0F\n\
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
    
    let encrypted_ehr = aead::AEADCipher::encrypt(
        &aead_key,
        &nonce,
        ehr_data,
        associated_data,
    ).unwrap();
    
    // Extract tag
    let tag_start = encrypted_ehr.len().saturating_sub(16);
    let mut tag = [0u8; 16];
    tag.copy_from_slice(&encrypted_ehr[tag_start..]);
    
    // Pack and encrypt with DIBTD
    let packed_params = aead::AEADCipher::pack_aead_params(&aead_key, &nonce, &tag);
    let ciphertext = encryption::DIBTDEncryption::encrypt(
        &packed_params,
        &group_id.id,
        &mpk,
    ).unwrap();
    
    // Generate decryption shares
    let mut decryption_shares = Vec::new();
    for i in 1..=2 {
        if let Some(private_share) = private_shares.get(&i) {
            let dec_share = encryption::DIBTDEncryption::share_decrypt(
                &ciphertext,
                private_share,
            ).unwrap();
            decryption_shares.push(dec_share);
        }
    }
    
    // Decrypt DIBTD
    let decrypted_params = encryption::DIBTDEncryption::decrypt(
        &ciphertext,
        &decryption_shares,
        2,
    ).unwrap();
    
    // Unpack and decrypt AEAD
    let (recovered_key, recovered_nonce, _) = 
        aead::AEADCipher::unpack_aead_params(&decrypted_params).unwrap();
    
    // Fixed: Pass the full encrypted_ehr (including tag) to decrypt
    let decrypted_ehr = aead::AEADCipher::decrypt(
        &recovered_key,
        &recovered_nonce,
        &encrypted_ehr,  // Pass full ciphertext with tag
        associated_data,
    ).unwrap();
    
    assert_eq!(ehr_data.to_vec(), decrypted_ehr);
}

#[test]
fn test_proof_verification() {
    // Setup minimal system
    let n = 3;
    let t = 2;
    
    let mut dkg = dkg::DKGProtocol::new(n, t).unwrap();
    for i in 1..=n {
        dkg.init_participant(i).unwrap();
    }
    
    let mut all_shares = HashMap::new();
    for from in 1..=n {
        let shares = dkg.distribute_shares(from).unwrap();
        all_shares.insert(from, shares);
    }
    
    for to in 1..=n {
        for (from, shares_map) in &all_shares {
            if let Some(share) = shares_map.get(&to) {
                dkg.receive_shares(to, *from, *share).unwrap();
            }
        }
    }
    
    let (mpk, master_shares) = dkg.finalize().unwrap();
    
    let group_id = GroupIdentity {
        id: "test_group".to_string(),
        threshold: 2,
        members: 3,
    };
    
    let private_shares = dkg::distributed_keygen(&master_shares, &group_id, t).unwrap();
    
    let message = b"Test";
    let ciphertext = encryption::DIBTDEncryption::encrypt(
        message,
        &group_id.id,
        &mpk,
    ).unwrap();
    
    // Generate share and proof
    let private_share = private_shares.get(&1).unwrap();
    let dec_share = encryption::DIBTDEncryption::share_decrypt(
        &ciphertext,
        private_share,
    ).unwrap();
    
    let proof = crypto::ZKProof::prove_share(
        private_share,
        &dec_share,
        "test_context",
    ).unwrap();
    
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
    
    let mut dkg = dkg::DKGProtocol::new(n, t).unwrap();
    for i in 1..=n {
        dkg.init_participant(i).unwrap();
    }
    
    let mut all_shares = HashMap::new();
    for from in 1..=n {
        let shares = dkg.distribute_shares(from).unwrap();
        all_shares.insert(from, shares);
    }
    
    for to in 1..=n {
        for (from, shares_map) in &all_shares {
            if let Some(share) = shares_map.get(&to) {
                dkg.receive_shares(to, *from, *share).unwrap();
            }
        }
    }
    
    let (mpk, master_shares) = dkg.finalize().unwrap();
    
    let group_id = GroupIdentity {
        id: "test_group".to_string(),
        threshold: 3,
        members: 5,
    };
    
    let private_shares = dkg::distributed_keygen(&master_shares, &group_id, t).unwrap();
    
    // Verify threshold consistency
    let is_consistent = threshold::ThresholdOperations::verify_threshold_consistency(
        &private_shares,
        &mpk,
        &group_id.id,
        group_id.threshold,
    ).unwrap();
    
    assert!(is_consistent);
}