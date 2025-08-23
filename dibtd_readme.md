# DIBTD ePHR - Distributed Identity-Based Threshold Decryption for Electronic Personal Health Records

A Rust implementation of a distributed identity-based threshold decryption scheme for secure sharing of electronic personal health records (ePHR), based on the paper's cryptographic protocols.

## Features

- **Distributed Key Generation (DKG)**: Pedersen's DKG protocol for distributed master key generation
- **Threshold Decryption**: Requires collaboration of multiple authorized parties to decrypt
- **Identity-Based Encryption**: Group-based encryption without individual public key certificates
- **AEAD Integration**: Hybrid encryption for efficient handling of large medical data
- **Zero-Knowledge Proofs**: Schnorr signatures for proving knowledge of secret shares
- **Secp256k1 Elliptic Curve**: Industry-standard curve used in Bitcoin and Ethereum

## Architecture

The system consists of several key components:

1. **DKGC (Distributed Key Generation Center)**: Multiple nodes that collaboratively generate and manage cryptographic keys
2. **Medical Server**: Distributed storage for encrypted ePHR data
3. **Healthcare Professionals**: Doctors and superintendents who collaborate to decrypt patient data
4. **Patients**: Data owners who encrypt their ePHR for secure storage

## Project Structure

```
dibtd-ephr/
├── src/
│   ├── lib.rs           # Main library module
│   ├── types.rs         # Core data structures
│   ├── errors.rs        # Error handling
│   ├── utils.rs         # Utility functions
│   ├── dkg.rs           # Distributed key generation
│   ├── encryption.rs    # Encryption/decryption operations
│   ├── crypto.rs        # Cryptographic primitives
│   ├── aead.rs          # AEAD encryption for large data
│   ├── threshold.rs     # Threshold cryptography operations
│   └── main.rs          # Example usage
├── benches/
│   └── dibtd_benchmark.rs  # Performance benchmarks
├── tests/
│   └── integration_tests.rs # Integration tests
├── Cargo.toml           # Project configuration
└── README.md            # This file
```

## Installation

Add to your `Cargo.toml`:

```toml
[dependencies]
dibtd-ephr = { path = "path/to/dibtd-ephr" }
```

## Usage Example

```rust
use dibtd_ephr::*;

// Initialize DKG with 5 nodes, threshold 3
let mut dkg = dkg::DKGProtocol::new(5, 3)?;

// Setup participants and generate master keys
// ... (see main.rs for complete example)

// Create group identity for healthcare department
let group_id = GroupIdentity {
    id: "cardiology_dept_2024".to_string(),
    threshold: 2,  // Need 2 doctors to decrypt
    members: 4,     // Total department members
};

// Encrypt patient data
let ehr_data = b"Patient medical record...";
let ciphertext = DIBTDEncryption::encrypt(ehr_data, &group_id.id, &mpk)?;

// Threshold decryption by authorized doctors
// ... (requires collaboration of threshold number of members)
```

## Security Features

- **No Single Point of Failure**: Master secret key is distributed across multiple DKGC nodes
- **Threshold Security**: Requires minimum number of participants to decrypt
- **Verifiable Secret Sharing**: All shares can be verified for correctness
- **Tamper Detection**: Integrity verification for stored and transmitted data
- **Forward Secrecy**: Each encryption uses fresh randomness

## Performance

Run benchmarks with:

```bash
cargo bench
```

Benchmark results on modern hardware:

- DKG Setup (5 nodes): ~10ms
- Encryption (256 bytes): ~2ms
- Share Decryption: ~1ms
- Threshold Decryption (2 shares): ~3ms
- AEAD (10KB): ~100μs

## Testing

Run tests with:

```bash
cargo test
```

Tests include:

- Full system integration tests
- Threshold security verification
- AEAD hybrid encryption
- Zero-knowledge proof validation
- Consistency checks

## Security Considerations

1. **Threshold Selection**: Choose `t > n/2` to prevent collusion attacks
2. **Secure Channels**: Use TLS for communication between participants
3. **Key Storage**: Private key shares must be securely stored
4. **Randomness**: System security depends on quality randomness
5. **Side Channels**: Implementation doesn't protect against timing attacks

## Dependencies

- `secp256k1`: Elliptic curve operations
- `sha2`, `sha3`: Cryptographic hash functions
- `aes-gcm`: Authenticated encryption
- `rand`: Cryptographic randomness
- `num-bigint`: Large integer arithmetic for Lagrange interpolation

## License

This implementation is for research and educational purposes.

## References

Based on the paper: "Distributed Identity-Based Threshold Decryption Scheme for Electronic Personal Health Records Sharing"
