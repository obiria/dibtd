use dibtd_ephr::*;
use std::collections::HashMap;

fn main() -> Result<()> {
    println!("DIBTD ePHR System Demo\n");
    
    // System parameters
    let n = 5;  // Total DKGC nodes
    let t = 3;  // Threshold for DKGC
    let group_members = 4;  // Doctors + Superintendent
    let group_threshold = 2;  // Threshold for decryption
    
    println!("Step 1: Distributed Key Generation");
    println!("  - Initializing {} DKGC nodes with threshold {}", n, t);
    
    // Initialize DKG protocol
    let mut dkg = dkg::DKGProtocol::new(n, t)?;
    
    // Initialize all participants
    for i in 1..=n {
        dkg.init_participant(i)?;
    }
    
    // Distribute shares between participants
    let mut all_shares = HashMap::new();
    for from in 1..=n {
        let shares = dkg.distribute_shares(from)?;
        all_shares.insert(from, shares);
    }
    
    // Each participant receives shares from others
    for to in 1..=n {
        for (from, shares_map) in &all_shares {
            if let Some(share) = shares_map.get(&to) {
                dkg.receive_shares(to, *from, *share)?;
            }
        }
    }
    
    // Verify shares
    for i in 1..=n {
        let valid = dkg.verify_shares(i)?;
        println!("  - Node {} share verification: {}", i, if valid { "✓" } else { "✗" });
    }
    
    // Finalize DKG to get master keys
    let (mpk, master_shares) = dkg.finalize()?;
    println!("  - Master public key generated successfully");
    
    println!("\nStep 2: Group Key Generation");
    let group_id = GroupIdentity {
        id: "cardiology_dept_2024".to_string(),
        threshold: group_threshold,
        members: group_members,
    };
    println!("  - Generating keys for group: {}", group_id.id);
    println!("  - Group members: {}, threshold: {}", group_members, group_threshold);
    
    // Generate private keys for the group
    let private_shares = dkg::distributed_keygen(&master_shares, &group_id, t)?;
    println!("  - Generated {} private key shares", private_shares.len());
    
    println!("\nStep 3: Data Encryption (Patient)");
    
    // Patient's ePHR data
    let ehr_data = b"Patient: John Doe\nBlood Pressure: 120/80\nHeart Rate: 72 bpm\nDiagnosis: Normal";
    
    // Generate AEAD key and encrypt the actual data
    let aead_key = aead::AEADCipher::generate_key();
    let nonce = aead::AEADCipher::generate_nonce();
    let associated_data = b"Medical Record 2024-01-15";
    
    let encrypted_ehr = aead::AEADCipher::encrypt(
        &aead_key,
        &nonce,
        ehr_data,
        associated_data,
    )?;
    
    // Extract tag (last 16 bytes of AEAD ciphertext)
    let tag_start = encrypted_ehr.len().saturating_sub(16);
    let mut tag = [0u8; 16];
    tag.copy_from_slice(&encrypted_ehr[tag_start..]);
    
    // Pack AEAD parameters for DIBTD encryption
    let packed_params = aead::AEADCipher::pack_aead_params(&aead_key, &nonce, &tag);
    
    // Encrypt the AEAD parameters with DIBTD
    let ciphertext = encryption::DIBTDEncryption::encrypt(
        &packed_params,
        &group_id.id,
        &mpk,
    )?;
    
    println!("  - ePHR data encrypted successfully");
    println!("  - Original size: {} bytes", ehr_data.len());
    println!("  - Encrypted size: {} bytes", encrypted_ehr.len());
    
    println!("\nStep 4: Threshold Decryption (Doctors)");
    
    // Simulate threshold number of doctors attempting to decrypt
    let mut decryption_shares = Vec::new();
    let participating_members = vec![1, 3];  // Two doctors collaborate
    
    println!("  - Members {} participating in decryption", 
             participating_members.iter().map(|i| i.to_string()).collect::<Vec<_>>().join(", "));
    
    for &member_id in &participating_members {
        if let Some(private_share) = private_shares.get(&member_id) {
            let dec_share = encryption::DIBTDEncryption::share_decrypt(
                &ciphertext,
                private_share,
            )?;
            
            // Generate and verify proof
            let proof = crypto::ZKProof::prove_share(
                private_share,
                &dec_share,
                "decryption_proof",
            )?;
            
            let valid = crypto::ZKProof::verify_share(
                &proof,
                &private_share.verification_key,
                "decryption_proof",
            );
            
            println!("    - Member {} generated share: {}", member_id, if valid { "✓" } else { "✗" });
            decryption_shares.push(dec_share);
        }
    }
    
    // Combine shares to decrypt
    let decrypted_params = encryption::DIBTDEncryption::decrypt(
        &ciphertext,
        &decryption_shares,
        group_threshold,
    )?;
    
    // Unpack AEAD parameters
    let (recovered_key, recovered_nonce, _recovered_tag) = 
        aead::AEADCipher::unpack_aead_params(&decrypted_params)?;
    
    // Decrypt the actual ePHR data
    // IMPORTANT: Pass the full encrypted_ehr (including tag) to decrypt
    let decrypted_ehr = aead::AEADCipher::decrypt(
        &recovered_key,
        &recovered_nonce,
        &encrypted_ehr,  // Pass full ciphertext with tag
        associated_data,
    )?;
    
    println!("  - Decryption successful!");
    println!("\nRecovered ePHR Data:");
    println!("  {}", String::from_utf8_lossy(&decrypted_ehr));
    
    // Test with insufficient shares
    println!("\nStep 5: Testing Security (Insufficient Shares)");
    let insufficient_shares = vec![decryption_shares[0].clone()];
    
    match encryption::DIBTDEncryption::decrypt(&ciphertext, &insufficient_shares, group_threshold) {
        Err(DIBTDError::InsufficientShares(got, need)) => {
            println!("  - Security check passed: {} shares insufficient (need {})", got, need);
        }
        _ => {
            println!("  - Security check failed!");
        }
    }
    
    Ok(())
}