use dibtd_ephr::*;
use std::collections::HashMap;
use std::time::Instant;

fn main() -> Result<()> {
    println!("╔══════════════════════════════════════════════════════════════════════════════╗");
    println!("║                           DIBTD ePHR System Demo                            ║");
    println!("║                Identity-Based Threshold Decryption for ePHR                 ║");
    println!("╚══════════════════════════════════════════════════════════════════════════════╝");
    println!();

    // System parameters
    let n = 5; // Total DKGC nodes
    let t = 3; // Threshold for DKGC
    let group_members = 4; // Doctors + Superintendent
    let group_threshold = 2; // Threshold for decryption

    println!("System Configuration:");
    println!("─────────────────────");
    println!("• DKGC Nodes: {}", n);
    println!("• DKGC Threshold: {}", t);
    println!("• Group Members: {}", group_members);
    println!("• Decryption Threshold: {}", group_threshold);
    println!();

    println!("Step 1: Distributed Key Generation");
    println!("──────────────────────────────────");
    println!("Initializing {} DKGC nodes with threshold {}...", n, t);

    let dkg_start = Instant::now();

    // Initialize DKG protocol
    let mut dkg = dkg::DKGProtocol::new(n, t)?;

    // Initialize all participants
    for i in 1..=n {
        dkg.init_participant(i)?;
    }
    println!("All {} participants initialized", n);

    // Distribute shares between participants
    let mut all_shares = HashMap::new();
    for from in 1..=n {
        let shares = dkg.distribute_shares(from)?;
        all_shares.insert(from, shares);
    }
    println!("Shares distributed among all participants");

    // Each participant receives shares from others
    for to in 1..=n {
        for (from, shares_map) in &all_shares {
            if let Some(share) = shares_map.get(&to) {
                dkg.receive_shares(to, *from, *share)?;
            }
        }
    }
    println!("All shares received and processed");

    // Verify shares
    for i in 1..=n {
        let valid = dkg.verify_shares(i)?;
        if !valid {
            return Err(DIBTDError::InvalidShareVerification);
        }
    }
    println!("All share verifications passed");

    // Finalize DKG to get master keys
    let (mpk, master_shares) = dkg.finalize()?;
    let dkg_time = dkg_start.elapsed();

    println!("Master public key generated successfully");
    println!("  DKG Setup Time: {:.3}ms", dkg_time.as_millis());
    println!();

    println!("Step 2: Group Key Generation");
    println!("────────────────────────────");

    let group_id = GroupIdentity {
        id: "cardiology_dept_2024".to_string(),
        threshold: group_threshold,
        members: group_members,
    };

    println!("Generating keys for group: {}", group_id.id);
    println!(
        "Group configuration: {} members, threshold {}",
        group_members, group_threshold
    );

    let keygen_start = Instant::now();

    // Generate private keys for the group
    let private_shares = dkg::distributed_keygen(&master_shares, &group_id, t)?;
    let keygen_time = keygen_start.elapsed();

    println!("Generated {} private key shares", private_shares.len());
    println!("  KeyGen Time: {:.3}ms", keygen_time.as_millis());
    println!();

    println!("Step 3: Data Encryption (Patient)");
    println!("──────────────────────────────────");

    // Patient's ePHR data
    let ehr_data = b"PATIENT ELECTRONIC HEALTH RECORD\n\
                     ================================\n\
                     Patient ID: 12345\n\
                     Name: John Doe\n\
                     Date of Birth: 1980-05-15\n\
                     \n\
                     VITAL SIGNS (Latest Visit):\n\
                     Blood Pressure: 120/80 mmHg\n\
                     Heart Rate: 72 bpm\n\
                     Temperature: 98.6 Fahrenheit\n\
                     Respiratory Rate: 16/min\n\
                     \n\
                     LABORATORY RESULTS:\n\
                     Glucose: 95 mg/dL (Normal)\n\
                     Cholesterol: 180 mg/dL\n\
                     HDL: 50 mg/dL\n\
                     LDL: 110 mg/dL\n\
                     \n\
                     DIAGNOSIS:\n\
                     Hypertension, Stage 1\n\
                     \n\
                     PRESCRIBED MEDICATIONS:\n\
                     - Lisinopril 10mg daily\n\
                     - Atorvastatin 20mg daily\n\
                     \n\
                     PHYSICIAN NOTES:\n\
                     Patient shows good compliance with medication.\n\
                     Recommend lifestyle modifications including\n\
                     regular exercise and dietary changes.\n\
                     Follow-up in 3 months.";

    let encrypt_start = Instant::now();

    // Generate AEAD key and encrypt the actual data
    let aead_key = aead::AEADCipher::generate_key();
    let nonce = aead::AEADCipher::generate_nonce();
    let associated_data = b"Medical Record 2024-01-15 - Cardiology Department";

    let encrypted_ehr = aead::AEADCipher::encrypt(&aead_key, &nonce, ehr_data, associated_data)?;

    // Extract tag (last 16 bytes of AEAD ciphertext)
    let tag_start = encrypted_ehr.len().saturating_sub(16);
    let mut tag = [0u8; 16];
    tag.copy_from_slice(&encrypted_ehr[tag_start..]);

    // Pack AEAD parameters for DIBTD encryption
    let packed_params = aead::AEADCipher::pack_aead_params(&aead_key, &nonce, &tag);

    // Encrypt the AEAD parameters with DIBTD
    let ciphertext = encryption::DIBTDEncryption::encrypt(&packed_params, &group_id.id, &mpk)?;

    let encrypt_time = encrypt_start.elapsed();

    println!("ePHR data encrypted successfully");
    println!("  Original data size: {} bytes", ehr_data.len());
    println!("  Encrypted data size: {} bytes", encrypted_ehr.len());
    println!("  Encryption time: {:.3}ms", encrypt_time.as_millis());
    println!();

    println!("Step 4: Threshold Decryption (Medical Staff)");
    println!("─────────────────────────────────────────────");

    // Simulate threshold number of doctors attempting to decrypt
    let participating_members = vec![1, 3]; // Two doctors collaborate

    println!(
        "Medical staff members {} participating in decryption",
        participating_members
            .iter()
            .map(|i| i.to_string())
            .collect::<Vec<_>>()
            .join(", ")
    );

    let decrypt_start = Instant::now();
    let mut decryption_shares = Vec::new();

    for &member_id in &participating_members {
        if let Some(private_share) = private_shares.get(&member_id) {
            let share_start = Instant::now();

            let dec_share = encryption::DIBTDEncryption::share_decrypt(&ciphertext, private_share)?;

            // Generate and verify proof
            let proof =
                crypto::ZKProof::prove_share(private_share, &dec_share, "cardiology_access_2024")?;

            let valid = crypto::ZKProof::verify_share(
                &proof,
                &private_share.verification_key,
                "cardiology_access_2024",
            );

            let share_time = share_start.elapsed();

            if valid {
                println!(
                    "  Member {} generated valid share ({:.3}ms)",
                    member_id,
                    share_time.as_millis()
                );
                decryption_shares.push(dec_share);
            } else {
                println!("  ✗ Member {} proof verification failed", member_id);
                return Err(DIBTDError::InvalidProof);
            }
        }
    }

    // Combine shares to decrypt
    let decrypted_params =
        encryption::DIBTDEncryption::decrypt(&ciphertext, &decryption_shares, group_threshold)?;

    // Unpack AEAD parameters
    let (recovered_key, recovered_nonce, _recovered_tag) =
        aead::AEADCipher::unpack_aead_params(&decrypted_params)?;

    // Decrypt the actual ePHR data
    let decrypted_ehr = aead::AEADCipher::decrypt(
        &recovered_key,
        &recovered_nonce,
        &encrypted_ehr,
        associated_data,
    )?;

    let decrypt_time = decrypt_start.elapsed();

    println!("Threshold decryption successful!");
    println!("  Decryption time: {:.3}ms", decrypt_time.as_millis());
    println!();

    println!("Step 5: Data Verification");
    println!("─────────────────────────");

    if decrypted_ehr == ehr_data {
        println!("Data integrity verified - decryption successful");
        println!();

        println!("Recovered ePHR Data:");
        println!("══════════════════");
        let recovered_text = String::from_utf8_lossy(&decrypted_ehr);
        println!("{}", recovered_text);
    } else {
        println!("✗ Data integrity check failed");
        return Err(DIBTDError::DecryptionFailed);
    }

    println!();
    println!("Step 6: Security Testing");
    println!("────────────────────────");

    // Test with insufficient shares
    let insufficient_shares = vec![decryption_shares[0].clone()];

    match encryption::DIBTDEncryption::decrypt(&ciphertext, &insufficient_shares, group_threshold) {
        Err(DIBTDError::InsufficientShares(got, need)) => {
            println!(
                "Security verified: {} share insufficient (need {})",
                got, need
            );
        }
        Ok(_) => {
            println!("✗ Security breach: insufficient shares succeeded!");
            return Err(DIBTDError::DecryptionFailed);
        }
        Err(e) => {
            println!("✗ Unexpected error during security test: {}", e);
            return Err(e);
        }
    }

    // Test threshold operations
    let is_consistent = threshold::ThresholdOperations::verify_threshold_consistency(
        &private_shares,
        &mpk,
        &group_id.id,
        group_threshold,
    )?;

    if is_consistent {
        println!("Threshold consistency verified");
    } else {
        println!("✗ Threshold consistency check failed");
    }

    println!();
    println!("Performance Summary:");
    println!("───────────────────");
    println!("• DKG Setup: {:.3}ms", dkg_time.as_millis());
    println!("• Key Generation: {:.3}ms", keygen_time.as_millis());
    println!("• Data Encryption: {:.3}ms", encrypt_time.as_millis());
    println!("• Threshold Decryption: {:.3}ms", decrypt_time.as_millis());
    println!(
        "• Total Operation Time: {:.3}ms",
        (dkg_time + keygen_time + encrypt_time + decrypt_time).as_millis()
    );

    println!();
    println!("╔══════════════════════════════════════════════════════════════════════════════╗");
    println!("║                        DIBTD ePHR Demo Completed Successfully               ║");
    println!("║                                                                              ║");
    println!("║  The system has demonstrated:                                               ║");
    println!("║  • Secure distributed key generation                                       ║");
    println!("║  • Identity-based threshold encryption                                     ║");
    println!("║  • Zero-knowledge proof verification                                       ║");
    println!("║  • Threshold decryption with access control                               ║");
    println!("║  • Data integrity and confidentiality protection                          ║");
    println!("╚══════════════════════════════════════════════════════════════════════════════╝");

    Ok(())
}
