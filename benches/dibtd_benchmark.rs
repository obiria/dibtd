use criterion::{black_box, criterion_group, criterion_main, Criterion, BenchmarkId};
use dibtd_ephr::*;
use std::collections::HashMap;

fn setup_system(n: usize, t: usize) -> (MasterPublicKey, HashMap<usize, MasterSecretShare>) {
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
    
    dkg.finalize().unwrap()
}

fn benchmark_dkg(c: &mut Criterion) {
    let mut group = c.benchmark_group("DKG Protocol");
    
    for n in [3, 5, 7].iter() {
        let t = (n * 2) / 3;
        group.bench_with_input(
            BenchmarkId::from_parameter(format!("n={},t={}", n, t)),
            &(n, t),
            |b, &(n, t)| {
                b.iter(|| {
                    setup_system(*n, t);
                });
            },
        );
    }
    
    group.finish();
}

fn benchmark_encryption(c: &mut Criterion) {
    let (mpk, _) = setup_system(5, 3);
    let group_id = "test_group";
    
    let mut group = c.benchmark_group("Encryption");
    
    for size in [32, 256, 1024, 4096].iter() {
        let message = vec![0u8; *size];
        
        group.bench_with_input(
            BenchmarkId::from_parameter(format!("{} bytes", size)),
            &message,
            |b, message| {
                b.iter(|| {
                    encryption::DIBTDEncryption::encrypt(
                        black_box(message),
                        black_box(group_id),
                        black_box(&mpk),
                    ).unwrap();
                });
            },
        );
    }
    
    group.finish();
}

fn benchmark_share_decryption(c: &mut Criterion) {
    let (mpk, master_shares) = setup_system(5, 3);
    let group_id = GroupIdentity {
        id: "test_group".to_string(),
        threshold: 2,
        members: 4,
    };
    
    let private_shares = dkg::distributed_keygen(&master_shares, &group_id, 3).unwrap();
    let message = vec![0u8; 256];
    let ciphertext = encryption::DIBTDEncryption::encrypt(&message, &group_id.id, &mpk).unwrap();
    
    c.bench_function("Share Decryption", |b| {
        let private_share = private_shares.get(&1).unwrap();
        b.iter(|| {
            encryption::DIBTDEncryption::share_decrypt(
                black_box(&ciphertext),
                black_box(private_share),
            ).unwrap();
        });
    });
}

fn benchmark_threshold_decryption(c: &mut Criterion) {
    let (mpk, master_shares) = setup_system(5, 3);
    let group_id = GroupIdentity {
        id: "test_group".to_string(),
        threshold: 2,
        members: 4,
    };
    
    let private_shares = dkg::distributed_keygen(&master_shares, &group_id, 3).unwrap();
    let message = vec![0u8; 256];
    let ciphertext = encryption::DIBTDEncryption::encrypt(&message, &group_id.id, &mpk).unwrap();
    
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
    
    c.bench_function("Threshold Decryption", |b| {
        b.iter(|| {
            encryption::DIBTDEncryption::decrypt(
                black_box(&ciphertext),
                black_box(&decryption_shares),
                black_box(2),
            ).unwrap();
        });
    });
}

fn benchmark_aead(c: &mut Criterion) {
    let key = aead::AEADCipher::generate_key();
    let nonce = aead::AEADCipher::generate_nonce();
    let associated_data = b"Medical Record";
    
    let mut group = c.benchmark_group("AEAD Operations");
    
    for size in [1024, 10240, 102400].iter() {
        let plaintext = vec![0u8; *size];
        
        group.bench_with_input(
            BenchmarkId::new("Encrypt", format!("{} bytes", size)),
            &plaintext,
            |b, plaintext| {
                b.iter(|| {
                    aead::AEADCipher::encrypt(
                        black_box(&key),
                        black_box(&nonce),
                        black_box(plaintext),
                        black_box(associated_data),
                    ).unwrap();
                });
            },
        );
        
        let ciphertext = aead::AEADCipher::encrypt(
            &key,
            &nonce,
            &plaintext,
            associated_data,
        ).unwrap();
        
        group.bench_with_input(
            BenchmarkId::new("Decrypt", format!("{} bytes", size)),
            &ciphertext,
            |b, ciphertext| {
                b.iter(|| {
                    aead::AEADCipher::decrypt(
                        black_box(&key),
                        black_box(&nonce),
                        black_box(ciphertext),
                        black_box(associated_data),
                    ).unwrap();
                });
            },
        );
    }
    
    group.finish();
}

fn benchmark_proof_generation(c: &mut Criterion) {
    let (mpk, master_shares) = setup_system(5, 3);
    let group_id = GroupIdentity {
        id: "test_group".to_string(),
        threshold: 2,
        members: 4,
    };
    
    let private_shares = dkg::distributed_keygen(&master_shares, &group_id, 3).unwrap();
    let message = vec![0u8; 256];
    let ciphertext = encryption::DIBTDEncryption::encrypt(&message, &group_id.id, &mpk).unwrap();
    
    let private_share = private_shares.get(&1).unwrap();
    let dec_share = encryption::DIBTDEncryption::share_decrypt(&ciphertext, private_share).unwrap();
    
    c.bench_function("ZK Proof Generation", |b| {
        b.iter(|| {
            crypto::ZKProof::prove_share(
                black_box(private_share),
                black_box(&dec_share),
                black_box("proof_context"),
            ).unwrap();
        });
    });
    
    let proof = crypto::ZKProof::prove_share(private_share, &dec_share, "proof_context").unwrap();
    
    c.bench_function("ZK Proof Verification", |b| {
        b.iter(|| {
            crypto::ZKProof::verify_share(
                black_box(&proof),
                black_box(&private_share.verification_key),
                black_box("proof_context"),
            );
        });
    });
}

fn benchmark_end_to_end(c: &mut Criterion) {
    let (mpk, master_shares) = setup_system(5, 3);
    let group_id = GroupIdentity {
        id: "cardiology_dept".to_string(),
        threshold: 2,
        members: 4,
    };
    
    let private_shares = dkg::distributed_keygen(&master_shares, &group_id, 3).unwrap();
    
    let mut group = c.benchmark_group("End-to-End");
    
    for size in [1024, 10240, 102400].iter() {
        let ehr_data = vec![0u8; *size];
        
        group.bench_with_input(
            BenchmarkId::from_parameter(format!("{} bytes", size)),
            &ehr_data,
            |b, ehr_data| {
                b.iter(|| {
                    // Encrypt with AEAD
                    let aead_key = aead::AEADCipher::generate_key();
                    let nonce = aead::AEADCipher::generate_nonce();
                    let associated_data = b"Medical Record";
                    
                    let encrypted_ehr = aead::AEADCipher::encrypt(
                        &aead_key,
                        &nonce,
                        ehr_data,
                        associated_data,
                    ).unwrap();
                    
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
                    
                    // Combine shares to decrypt
                    let decrypted_params = encryption::DIBTDEncryption::decrypt(
                        &ciphertext,
                        &decryption_shares,
                        2,
                    ).unwrap();
                    
                    // Unpack and decrypt with AEAD
                    let (recovered_key, recovered_nonce, _) = 
                        aead::AEADCipher::unpack_aead_params(&decrypted_params).unwrap();
                    
                    aead::AEADCipher::decrypt(
                        &recovered_key,
                        &recovered_nonce,
                        &encrypted_ehr[..tag_start],
                        associated_data,
                    ).unwrap();
                });
            },
        );
    }
    
    group.finish();
}

criterion_group!(
    benches,
    benchmark_dkg,
    benchmark_encryption,
    benchmark_share_decryption,
    benchmark_threshold_decryption,
    benchmark_aead,
    benchmark_proof_generation,
    benchmark_end_to_end
);

criterion_main!(benches);