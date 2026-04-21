#!/usr/bin/env bash
#
# Runs every PVSS benchmark in this repo and prints transcript sizes for all
# configured (n, t) pairs.
#
# Pass `--features chunks-8bit` (or any other cargo args) to switch to 8-bit
# chunks (m=32, B=2^8). Default is 16-bit chunks (m=16, B=2^16).

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"

cd "${REPO_ROOT}"

# Split args into feature-related (propagated to both `bench` and `test`) and
# other args (only for `bench`).
FEATURE_ARGS=()
BENCH_ONLY_ARGS=()
while [ $# -gt 0 ]; do
    case "$1" in
        --features)
            FEATURE_ARGS+=("$1" "${2-}")
            shift 2
            ;;
        --features=*|--no-default-features|--all-features)
            FEATURE_ARGS+=("$1")
            shift
            ;;
        *)
            BENCH_ONLY_ARGS+=("$1")
            shift
            ;;
    esac
done

# macOS ships bash 3.2, which treats "${arr[@]}" on an empty array as unbound
# under `set -u`. The `${arr[@]+…}` guard only expands when the array is set.
echo "== Running Criterion benchmarks: deal + verify =="
cargo bench ${FEATURE_ARGS[@]+"${FEATURE_ARGS[@]}"} --bench groth21 ${BENCH_ONLY_ARGS[@]+"${BENCH_ONLY_ARGS[@]}"}

echo
echo "== Transcript sizes =="
cargo test --release ${FEATURE_ARGS[@]+"${FEATURE_ARGS[@]}"} --test transcript_sizes -- --ignored --nocapture transcript_sizes
