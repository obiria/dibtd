# DIBTD-ePHR: Identity-Based Threshold Decryption for Electronic Health Records

A Rust implementation of a cryptographic system for secure electronic health record (ePHR) storage and access control using identity-based threshold decryption.

## Overview

This system provides:

- **Distributed Key Generation (DKG)** with threshold cryptography
- **Identity-Based Encryption** for group-specific access control
- **Threshold Decryption** requiring multiple parties to collaborate
- **Zero-Knowledge Proofs** for share verification
- **AEAD Encryption** for efficient large data encryption
- **Comprehensive Benchmarking** for performance analysis

## Prerequisites

- **Rust 1.70+** (Install from [rustup.rs](https://rustup.rs/))
- **Git** for cloning the repository

```bash
# Install Rust (if not already installed)
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
source ~/.cargo/env

# Verify installation
rustc --version
cargo --version
```

## Project Structure

```
dibtd-ephr/
├── src/
│   ├── lib.rs              # Main library entry point
│   ├── main.rs             # Demo application
│   ├── dkg.rs              # Distributed Key Generation
│   ├── encryption.rs       # DIBTD encryption/decryption
│   ├── crypto.rs           # Zero-knowledge proofs
│   ├── aead.rs             # AEAD cipher operations
│   ├── threshold.rs        # Threshold cryptography utilities
│   ├── types.rs            # Core data structures
│   ├── utils.rs            # Cryptographic utilities
│   └── errors.rs           # Error handling
├── benches/
│   └── dibtd_benchmark.rs  # Criterion benchmarks
├── tests/
│   └── tests.rs            # Integration tests
├── comprehensive_benchmark.rs  # Real performance benchmarks
├── run_benchmarks.sh       # Benchmark runner script
├── Cargo.toml              # Project dependencies
└── README.md               # This file
```

## Core Components

### 1. **Distributed Key Generation (DKG)**

- **File**: `src/dkg.rs`
- **Purpose**: Generate master keys across multiple DKGC nodes
- **Key Functions**:
  - `DKGProtocol::new()` - Initialize protocol
  - `distribute_shares()` - Share distribution
  - `finalize()` - Generate master public key

### 2. **DIBTD Encryption**

- **File**: `src/encryption.rs`
- **Purpose**: Identity-based threshold encryption
- **Key Functions**:
  - `encrypt()` - Encrypt data for a group identity
  - `share_decrypt()` - Generate decryption shares
  - `decrypt()` - Combine shares to decrypt

### 3. **Zero-Knowledge Proofs**

- **File**: `src/crypto.rs`
- **Purpose**: Prove knowledge without revealing secrets
- **Key Functions**:
  - `prove_share()` - Generate ZK proof for decryption share
  - `verify_share()` - Verify ZK proof

### 4. **AEAD Encryption**

- **File**: `src/aead.rs`
- **Purpose**: Efficient authenticated encryption for large data
- **Key Functions**:
  - `encrypt()` - AES-GCM encryption
  - `decrypt()` - AES-GCM decryption
  - `pack_aead_params()` - Parameter packaging

## Quick Start

### 1. Clone and Build

```bash
git clone https://github.com/obiria/dibtd/tree/main
cd dibtd-ephr
cargo build --release
```

### 2. Run the Demo

The main demo shows a complete ePHR workflow:

```bash
cargo run --release
```

This demonstrates:

- Setting up a 5-node DKGC system with threshold 3
- Creating a 4-member medical group with threshold 2
- Encrypting patient health records
- Threshold decryption by medical staff
- Security verification

**Expected Output:**

```
╔══════════════════════════════════════════════════════════════════════════════╗
║                           DIBTD ePHR System Demo                            ║
║                Identity-Based Threshold Decryption for ePHR                 ║
╚══════════════════════════════════════════════════════════════════════════════╝

Step 1: Distributed Key Generation
──────────────────────────────────
All 5 participants initialized
Shares distributed among all participants
All shares received and processed
All share verifications passed
Master public key generated successfully
  DKG Setup Time: 2.456ms

Step 2: Group Key Generation
────────────────────────────
Generated 4 private key shares
  KeyGen Time: 1.234ms

...
```

### 3. Run Tests

Execute the comprehensive test suite:

```bash
# Run all tests
cargo test

# Run tests with output
cargo test -- --nocapture

# Run specific test
cargo test test_full_system_flow

# Run tests in release mode (faster)
cargo test --release
```

**Test Categories:**

- **Full System Flow**: End-to-end encryption/decryption
- **Security Tests**: Insufficient shares, proof verification
- **AEAD Integration**: Large data encryption with AES-GCM
- **Threshold Consistency**: Mathematical correctness
- **Error Conditions**: Invalid parameters and edge cases
- **Performance**: Scalability verification

### 4. Run Criterion Benchmarks

High-precision performance benchmarks using Criterion:

```bash
# Run all benchmarks
cargo bench

# Run specific benchmark group
cargo bench "DKG Protocol"
cargo bench "Encryption"
cargo bench "AEAD Operations"

# Generate HTML reports
cargo bench -- open
```

**Benchmark Categories:**

- **DKG Protocol**: Setup time for different node counts
- **Encryption**: Performance with various data sizes
- **Share Operations**: Decryption share generation/verification
- **AEAD Operations**: AES-GCM performance
- **ZK Proofs**: Proof generation and verification
- **End-to-End**: Complete workflow timing

**Results Location:**

- HTML reports: `target/criterion/report/index.html`
- Raw data: `target/criterion/`

### 5. Run Comprehensive Benchmarks

Real-world performance analysis with actual code execution:

```bash
# Make script executable
chmod +x run_benchmarks.sh

# Run comprehensive benchmarks
./run_benchmarks.sh
```

**What the script does:**

1. Sets up benchmark directory structure
2. Copies benchmark files to correct locations
3. Builds the benchmark suite in release mode
4. Runs comprehensive performance analysis
5. Generates detailed performance reports
6. Creates HTML reports with Criterion

**Output Files:**

- `benchmark_results_comprehensive.txt` - Detailed performance data
- `target/criterion/report/index.html` - Interactive HTML reports

### 6. Run Individual Comprehensive Benchmark

If you want to run just the comprehensive benchmark without the full script:

```bash
# Compile and run comprehensive benchmark directly
cargo run --bin comprehensive_benchmark --release
```

## Performance Expectations

### Typical Performance (on modern hardware):

- **DKG Setup (5 nodes)**: ~2-5ms
- **Key Generation**: ~1-3ms
- **Encryption (1KB data)**: ~0.1-0.5ms
- **Share Decryption**: ~0.1ms
- **ZK Proof Generation**: ~0.03ms
- **AES Encryption (1KB)**: ~0.002ms
- **End-to-End (1KB)**: ~1-5ms

### Scalability:

- **Node Count**: Tested up to 20 DKGC nodes
- **Group Size**: Supports up to 100+ members
- **Data Size**: Efficient for files up to several MB
- **Threshold**: Flexible threshold configurations

## Configuration Options

### System Parameters

Edit `src/main.rs` to modify demo parameters:

```rust
let n = 5;              // DKGC nodes
let t = 3;              // DKGC threshold
let group_members = 4;   // Group size
let group_threshold = 2; // Decryption threshold
```

### Benchmark Parameters

Edit `comprehensive_benchmark.rs` for different test scenarios:

```rust
let test_configs = vec![
    (3, 2), (5, 3), (7, 4), (10, 6), (15, 8), (20, 10)
];

let data_sizes_kb = vec![1, 4, 16, 64, 256, 1024];
```

## Troubleshooting

### Common Issues:

1. **Build Errors**:

   ```bash
   # Update Rust
   rustup update

   # Clean and rebuild
   cargo clean
   cargo build --release
   ```

2. **Test Failures**:

   ```bash
   # Run tests with backtrace
   RUST_BACKTRACE=1 cargo test

   # Run single-threaded
   cargo test -- --test-threads=1
   ```

3. **Benchmark Script Issues**:

   ```bash
   # Check permissions
   ls -la run_benchmarks.sh

   # Make executable
   chmod +x run_benchmarks.sh

   # Run with bash explicitly
   bash run_benchmarks.sh
   ```

4. **Performance Issues**:
   - Always use `--release` flag for performance testing
   - Ensure sufficient system resources
   - Close other applications during benchmarking

### Debug Mode vs Release Mode:

- **Debug Mode** (`cargo run`): Slower, includes debug symbols
- **Release Mode** (`cargo run --release`): Optimized, 10-100x faster

**Always use release mode for benchmarks and performance testing!**

## Dependencies

Key dependencies and their purposes:

- **secp256k1**: Elliptic curve cryptography
- **aes-gcm**: Authenticated encryption
- **sha2**: Hash functions
- **criterion**: Benchmarking framework
- **serde**: Serialization
- **thiserror**: Error handling
- **rand**: Random number generation

## Contributing

### Running Full Test Suite:

```bash
# Format code
cargo fmt

# Check for issues
cargo clippy

# Run all tests
cargo test --release

# Run benchmarks
cargo bench

# Run comprehensive benchmarks
./run_benchmarks.sh
```

### Adding New Tests:

Add tests to `tests/tests.rs`:

```rust
#[test]
fn test_new_feature() {
    // Test implementation
}
```

### Adding New Benchmarks:

Add benchmarks to `benches/dibtd_benchmark.rs`:

```rust
fn benchmark_new_feature(c: &mut Criterion) {
    c.bench_function("new_feature", |b| {
        b.iter(|| {
            // Benchmark code
        });
    });
}
```

## Security Considerations

- This is a **research implementation** - not production-ready
- Requires **secure channels** for share distribution
- **Key management** must be handled carefully
- **Side-channel attacks** not addressed
- **Formal security analysis** recommended before deployment

## License

This implementation is for research and educational purposes.c

## Citation

Based on the paper: "Distributed Identity-Based Threshold Decryption Scheme for Electronic Personal Health Records Sharing"

---

**For questions or issues, please check the troubleshooting section or create an issue in the repository.**
