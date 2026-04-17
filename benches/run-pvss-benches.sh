#!/usr/bin/env bash
#
# Runs every PVSS benchmark in this repo and prints transcript sizes for all
# configured (n, t) pairs.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"

cd "${REPO_ROOT}"

echo "== Running Criterion benchmarks: deal + verify =="
cargo bench --bench groth21 "$@"

echo
echo "== Running Criterion benchmarks: worst-case BSGS =="
echo "(full share worst case ≈ NUM_CHUNKS · (E-1) = 4080× one solve_signed)"
cargo bench --bench worst_case_decrypt "$@"

echo
echo "== Transcript sizes =="
cargo test --release --test transcript_sizes -- --ignored --nocapture transcript_sizes
