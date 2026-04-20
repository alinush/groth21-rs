//! Worst-case and honest-case share-decryption benchmarks for Groth21.
//!
//! The BSGS baby-step table is always **precomputed outside** `b.iter()` — the
//! [`Decryptor`] returned by `Groth21::decryptor` is built once per `(n, m)` and reused
//! across every `decrypt_share` call. What we measure is the per-share decryption cost
//! *after* setup, using the batch-optimal baby-table size.
//!
//! Two benches:
//!
//!   - `share-decrypt-honest/<n>`: run `Groth21::decrypt_share` on a real (honest)
//!     transcript. Each chunk's dlog is in `[0, B)` and hits the baby table directly,
//!     so this just costs `m` point subtractions + hash lookups.
//!   - `share-decrypt-worst/<n>`: feed the decryptor a synthetic ciphertext whose
//!     per-chunk targets are random G1 points. W.h.p. none have a dlog in
//!     `[-(Z-1), Z-1]`, so the solver exhausts every `δ ∈ [1, E-1]` for every chunk —
//!     i.e. the full `m · (E-1)` BSGS-query worst case. Because the baby-step table is
//!     sized for exactly this batch, total work is `O(√(m·(E-1)·Z))` not the naive
//!     `m·(E-1)·√Z`.
//!
//! Prints the BSGS sizing (`table_size`, `max_giant_steps`) on stderr for each `n` so
//! you can sanity-check timing against the theoretical model.

use std::ops::Mul;

use blstrs::{G1Projective, Scalar};
use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};
use ff::Field;
use group::Group;
use rand::thread_rng;

use e2e_vss::groth21::{
    random_encryption_keys, Decryptor, Groth21, PublicParameters, Transcript, NUM_CHUNKS,
};
use e2e_vss::pvss::{InputSecret, PvssScheme, SharingConfiguration};

fn random_g1() -> G1Projective {
    let mut rng = thread_rng();
    let s = Scalar::random(&mut rng);
    G1Projective::generator().mul(s)
}

fn print_decryptor_params(n: usize, d: &Decryptor) {
    eprintln!(
        "  n={:<3}  bsgs.table_size = {:>12}  bsgs.max_giant_steps = {:>8}",
        n,
        d.bsgs_table_size(),
        d.bsgs_max_giant_steps()
    );
}

fn setup(n: usize, decryptor: Decryptor) -> (SharingConfiguration, PublicParameters, Scalar, Transcript, Decryptor) {
    let mut rng = thread_rng();
    let t = (2 * n) / 3;
    let sc = SharingConfiguration::new(t + 1, n);
    let (dks, eks) = random_encryption_keys(n, &mut rng);
    let pp = PublicParameters::new(sc.clone(), eks, b"groth21-bench", b"e2e-vss");
    let secret = InputSecret::new_random(&sc, false, &mut rng);
    let transcript = Groth21::deal(&pp, &secret, &mut rng);
    assert!(Groth21::verify(&pp, &transcript));
    print_decryptor_params(n, &decryptor);
    (sc, pp, dks[0], transcript, decryptor)
}

fn bench_share_decrypt_honest(c: &mut Criterion) {
    let mut g = c.benchmark_group("groth21-decrypt");
    g.sample_size(10);

    // Best-case decryption: BSGS must cover [-(Z-1), Z-1] (soundness bound),
    // but batched only for k = m queries per share (no δ iteration).
    for &n in &[4usize, 8, 16, 32, 64, 128, 256, 512, 1024] {
        let decryptor = Decryptor::new_best_case(n);
        let (_sc, _pp, dk, transcript, decryptor) = setup(n, decryptor);
        g.throughput(Throughput::Elements(1));
        g.bench_function(BenchmarkId::new("share-decrypt-honest", n), |b| {
            b.iter(|| {
                let _ = Groth21::decrypt_share(&decryptor, &transcript, &dk, 0);
            })
        });
    }
    g.finish();
}

fn bench_share_decrypt_worst(c: &mut Criterion) {
    let mut g = c.benchmark_group("groth21-decrypt");
    g.sample_size(10);

    for &n in &[4usize, 8, 16, 32, 64, 128, 256, 512, 1024] {
        // Worst case needs the full batched table (sized for k = m·(E-1) queries).
        let decryptor = Decryptor::new(n);
        let (_sc, _pp, _dk, _transcript, decryptor) = setup(n, decryptor);
        // NUM_CHUNKS random G1 targets — w.h.p. each forces the solver to walk every
        // δ ∈ [1, E-1] and the full `max_giant_steps × 2` cursor iterations before
        // returning `None`. Exactly the per-share worst case.
        let targets: Vec<G1Projective> = (0..NUM_CHUNKS).map(|_| random_g1()).collect();
        let solver = decryptor.solver_for_bench();

        g.throughput(Throughput::Elements(1));
        g.bench_function(BenchmarkId::new("share-decrypt-worst", n), |b| {
            b.iter(|| {
                for tgt in &targets {
                    let _ = solver.solve(tgt);
                }
            })
        });
    }
    g.finish();
}

criterion_group!(
    name = decrypt_benches;
    config = Criterion::default();
    targets = bench_share_decrypt_honest, bench_share_decrypt_worst
);
criterion_main!(decrypt_benches);
