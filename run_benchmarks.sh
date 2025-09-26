#!/bin/bash

# DIBTD-ePHR Benchmark Runner Script
# This script sets up and runs the comprehensive benchmarks

echo "====================================="
echo "DIBTD-ePHR Benchmark Suite"
echo "====================================="
echo ""

# Check if we're in the right directory
if [ ! -f "Cargo.toml" ]; then
    echo "Error: Cargo.toml not found. Please run this script from the project root."
    exit 1
fi

# Create benchmark directory structure if it doesn't exist
echo "Setting up benchmark directory structure..."
mkdir -p benchmarks/src
mkdir -p benchmarks/benches


# Copy the comprehensive benchmark to the correct location
echo "Copying benchmark files..."
cp dibtd_comprehensive_benchmark.rs benchmarks/src/comprehensive_benchmark.rs 2>/dev/null || echo "Benchmark file already in place"
cp dibtd_benchmark.rs benchmarks/benches/dibtd_criterion.rs 2>/dev/null || echo "Criterion benchmark already in place"

# Copy the Cargo.toml for benchmarks
cp benchmark_cargo.toml benchmarks/Cargo.toml 2>/dev/null || echo "Cargo.toml already in place"

# Navigate to benchmarks directory
cd benchmarks

echo ""
echo "Building benchmark suite..."
cargo build --release

echo ""
echo "Running benchmarks..."
echo "1. Running comprehensive synthetic benchmarks..."
cargo run --release --bin comprehensive_benchmark

echo ""
echo "2. Running criterion benchmarks (this may take a while)..."
cargo bench

echo ""
echo "====================================="
echo "Benchmark Results"
echo "====================================="
echo ""

# Display results if they exist
echo ""
if [ -f "benchmark_results_complete.txt" ]; then
    echo "Actual benchmark results saved to: benchmarks/benchmark_results_complete.txt"
else
    echo "Warning: benchmark_results_actual.txt not found"
fi

echo ""
echo "Criterion HTML reports available at: benchmarks/target/criterion/report/index.html"
echo ""
echo "Benchmark suite complete!"