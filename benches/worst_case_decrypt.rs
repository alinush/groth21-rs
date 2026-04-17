//! Worst-case share-decryption benchmarks for Groth21.
//!
//! Per §DFINITY's-parameterization in <https://alinush.org/groth21>, decrypting a single
//! *chunk* of a possibly-adversarial ciphertext may require solving up to `E - 1 = 255`
//! discrete logs in a range of size `2Z - 1`, where `Z = 2·ℓ·n·m·(B-1)·(E-1)`
//! (a ~42-bit number for `n = 256, m = 16`). Decrypting a full *share* involves
//! `m = NUM_CHUNKS = 16` chunk decryptions, so the worst-case share-decryption cost is
//! bounded by `16 · 255 · sqrt(2Z-1)` group additions (plus hash lookups).
//!
//! Our BSGS does a single-pass signed scan over `[-(Z-1), Z-1]` using a straddling baby
//! table, so each chunk's BSGS solve in the worst case scans ~`sqrt(2Z-1)` giant steps
//! using only group additions — no scalar multiplications. A random target w.h.p. has no
//! dlog in range, forcing the solver to exhaust every δ ∈ [1, E-1] and walk the full
//! `max_j` iterations on both symmetric cursors — matching the true worst case.
//!
//! This file benches only the inner-loop worst-case BSGS solve (`solve_signed` on a
//! random target). The full share-decryption worst case is roughly `NUM_CHUNKS · (E-1)
//! = 16 · 255 = 4080×` this number — far too slow to run directly under Criterion even
//! for small `n` (hours per sample), so we measure the building block and leave the
//! multiplication to the reader.

use std::ops::Mul;

use blstrs::{G1Projective, Scalar};
use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};
use ff::Field;
use group::Group;
use rand::thread_rng;

use e2e_vss::groth21::{BabyStepGiantStep, NUM_CHUNKS};

fn random_g1() -> G1Projective {
    let mut rng = thread_rng();
    let s = Scalar::random(&mut rng);
    G1Projective::generator().mul(s)
}

/// `max_abs` passed to `BabyStepGiantStep::new`, matching what
/// `CheatingDealerDlogSolver::new(n, NUM_CHUNKS)` configures internally.
/// Kept in sync with `groth21::nizk_chunking::{CHALLENGE_BITS, NUM_ZK_REPETITIONS}`
/// and `groth21::chunking::CHUNK_SIZE`.
fn cheater_bsgs_max_abs(n: usize, m: usize) -> u64 {
    const CHALLENGE_BITS: usize = 8;
    const NUM_ZK_REPETITIONS: usize = 32;
    const CHUNK_SIZE: usize = 1 << 16;
    let scale_range: u64 = 1 << CHALLENGE_BITS;
    let ss = (n as u64) * (m as u64) * ((CHUNK_SIZE - 1) as u64) * (scale_range - 1);
    let zz = 2 * (NUM_ZK_REPETITIONS as u64) * ss;
    zz - 1
}

/// One worst-case BSGS `solve` (full signed scan). Multiply by `NUM_CHUNKS * (E-1) = 4080`
/// to get a rough upper bound on the full share-decryption worst case.
fn bench_bsgs_worst_case(c: &mut Criterion) {
    let mut g = c.benchmark_group("groth21-worst-case");
    g.sample_size(10);

    for &n in &[8usize, 16, 32, 64, 128, 256] {
        let max_abs = cheater_bsgs_max_abs(n, NUM_CHUNKS);
        let bsgs = BabyStepGiantStep::new(max_abs);
        let tgt = random_g1(); // w.h.p. has no dlog in [-max_abs, max_abs]

        g.throughput(Throughput::Elements(1));
        g.bench_function(BenchmarkId::new("bsgs-solve", n), |b| {
            b.iter(|| {
                let _ = bsgs.solve(&tgt);
            })
        });
    }
    g.finish();
}

criterion_group!(
    name = worst_case;
    config = Criterion::default();
    targets = bench_bsgs_worst_case
);
criterion_main!(worst_case);
