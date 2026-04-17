//! NIZK proof of correct chunking.
#![allow(clippy::needless_range_loop)]

use std::ops::{Mul, Neg};

use blstrs::{G1Projective, Scalar};
use group::Group;
use rand::distributions::{Distribution, Uniform};
use rand_chacha::rand_core::{RngCore as CRngCore, SeedableRng};
use rand_chacha::ChaCha20Rng;
use rand_core::{CryptoRng, RngCore};
use serde::{Deserialize, Serialize};

use crate::math::scalar::{hash_to_scalar, random_scalars};

use super::chunking::{CHUNK_SIZE, NUM_CHUNKS};
use super::encryption::CiphertextChunks;
use super::fiat_shamir::{FiatShamirProtocol, NIVSS_DOM_SEP};
use super::fs_util;
use super::utils::{batch_mul, get_xpowers, scalar_mult_exp, scalar_usize_mult_exp};

pub const SECURITY_LEVEL: usize = 256;

/// The number of parallel proofs handled by one challenge (called `l` in Groth21 §6.5).
pub const NUM_ZK_REPETITIONS: usize = 32;

pub const CHALLENGE_BITS: usize = (SECURITY_LEVEL + NUM_ZK_REPETITIONS - 1) / NUM_ZK_REPETITIONS;

pub const CHALLENGE_BYTES: usize = (CHALLENGE_BITS + 7) / 8;
const _: () = assert!(CHALLENGE_BYTES < std::mem::size_of::<usize>());

pub const CHALLENGE_MASK: usize = (1 << CHALLENGE_BITS) - 1;

#[derive(Clone, Debug)]
pub struct ChunkingWitness {
    scalars_r: [Scalar; NUM_CHUNKS],
    scalars_s: Vec<[Scalar; NUM_CHUNKS]>,
}

impl ChunkingWitness {
    pub fn new(scalars_r: [Scalar; NUM_CHUNKS], scalars_s: Vec<[Scalar; NUM_CHUNKS]>) -> Self {
        ChunkingWitness { scalars_r, scalars_s }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ZkProofChunkingError {
    InvalidProof,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct ProofChunking {
    y0: G1Projective,
    bb: Vec<G1Projective>,
    cc: Vec<G1Projective>,
    dd: Vec<G1Projective>,
    yy: G1Projective,
    z_r: Vec<Scalar>,
    z_s: [Scalar; NUM_ZK_REPETITIONS],
    z_beta: Scalar,
}

struct FirstMoveChunking {
    y0: G1Projective,
    bb: Vec<G1Projective>,
    cc: Vec<G1Projective>,
}

impl FirstMoveChunking {
    fn new(y0: G1Projective, bb: Vec<G1Projective>, cc: Vec<G1Projective>) -> Self {
        FirstMoveChunking { y0, bb, cc }
    }
}

struct SecondMoveChunking {
    z_s: Vec<Scalar>,
    dd: Vec<G1Projective>,
    yy: G1Projective,
}

impl SecondMoveChunking {
    fn from(z_s: &[Scalar], dd: &[G1Projective], yy: &G1Projective) -> Self {
        Self { z_s: z_s.to_owned(), dd: dd.to_owned(), yy: *yy }
    }
}

pub fn prove_chunking<R: RngCore + CryptoRng>(
    public_keys: &[G1Projective],
    ciphertexts: &CiphertextChunks,
    witness: &ChunkingWitness,
    rng: &mut R,
) -> ProofChunking {
    let m = ciphertexts.rr.len();
    let n = public_keys.len();

    let ss = n * m * (CHUNK_SIZE - 1) * CHALLENGE_MASK;
    let zz = 2 * NUM_ZK_REPETITIONS * ss;
    let range = zz - 1 + ss + 1;
    let zz_big = Scalar::from(zz as u64);
    let p_sub_s = Scalar::from(ss as u64).neg();

    let mut seed = [0u8; 32];
    rng.fill_bytes(&mut seed);
    let y0 = G1Projective::hash_to_curve(&seed, b"nizk-chunking-proof-y0", b"G1");

    let g1 = G1Projective::generator();
    let y0_g1_tbl = [y0, g1];

    let beta = random_scalars(NUM_ZK_REPETITIONS, rng);
    let bb: Vec<G1Projective> = beta.iter().map(|x| g1.mul(x)).collect();

    let (first_move, first_challenge, z_s) = loop {
        let sigma: [Scalar; NUM_ZK_REPETITIONS] =
            [(); NUM_ZK_REPETITIONS].map(|_| random_within_range(rng, range as u64) + &p_sub_s);

        let cc = {
            let mut cc = Vec::with_capacity(NUM_ZK_REPETITIONS);
            for i in 0..NUM_ZK_REPETITIONS {
                let b = beta[i];
                let s = sigma[i];
                cc.push(G1Projective::multi_exp(&y0_g1_tbl, &[b, s]));
            }
            cc
        };

        let first_move = FirstMoveChunking::new(y0, bb.clone(), cc);
        let first_challenge = ChunksOracle::new(public_keys, ciphertexts, &first_move).get_all_chunks(n, m);

        let iota: [usize; NUM_ZK_REPETITIONS] = std::array::from_fn(|i| i);
        let z_s = iota.map(|k| {
            let mut acc = Scalar::from(0);
            first_challenge.iter().zip(witness.scalars_s.iter()).for_each(|(e_i, s_i)| {
                e_i.iter().zip(s_i.iter()).for_each(|(e_ij, s_ij)| {
                    acc += Scalar::from(e_ij[k] as u64) * s_ij;
                });
            });
            acc += &sigma[k];
            acc
        });

        let zs_in_range = z_s.iter().map(|z| zz_big.gt(z) as isize).sum::<isize>() as usize == NUM_ZK_REPETITIONS;
        if zs_in_range {
            break (first_move, first_challenge, z_s);
        }
    };

    let delta = random_scalars(n + 1, rng);
    let dd: Vec<G1Projective> = delta.iter().map(|d| g1.mul(d)).collect();

    let yy = {
        let y0_and_pk: Vec<_> = std::iter::once(y0).chain(public_keys.iter().copied()).collect();
        G1Projective::multi_exp(&y0_and_pk, &delta)
    };

    let second_move = SecondMoveChunking::from(&z_s, &dd, &yy);
    let second_challenge = second_challenge(&first_challenge, &second_move);
    let xpowers = get_xpowers(&second_challenge, NUM_ZK_REPETITIONS);

    let mut z_r = Vec::with_capacity(first_challenge.len());
    let mut delta_idx = 1;
    for e_i in first_challenge.iter() {
        let mut xpow_e_ij = Vec::with_capacity(e_i.len());
        for j in 0..e_i.len() {
            xpow_e_ij.push(scalar_usize_mult_exp(&xpowers, &e_i[j]));
        }
        let z_rk = scalar_mult_exp(&witness.scalars_r, &xpow_e_ij) + &delta[delta_idx];
        z_r.push(z_rk);
        delta_idx += 1;
    }

    let z_beta = scalar_mult_exp(&beta, &xpowers) + &delta[0];

    ProofChunking {
        y0,
        bb,
        cc: first_move.cc,
        dd,
        yy,
        z_r,
        z_s,
        z_beta,
    }
}

pub fn verify_chunking(
    public_keys: &[G1Projective],
    ciphertexts: &CiphertextChunks,
    nizk: &ProofChunking,
) -> Result<(), ZkProofChunkingError> {
    let num_receivers = public_keys.len();
    require_eq(nizk.bb.len(), NUM_ZK_REPETITIONS)?;
    require_eq(nizk.cc.len(), NUM_ZK_REPETITIONS)?;
    require_eq(nizk.dd.len(), num_receivers + 1)?;
    require_eq(nizk.z_r.len(), num_receivers)?;
    require_eq(nizk.z_s.len(), NUM_ZK_REPETITIONS)?;

    let m = ciphertexts.rr.len();
    let n = public_keys.len();
    let ss = n * m * (CHUNK_SIZE - 1) * CHALLENGE_MASK;
    let zz = 2 * NUM_ZK_REPETITIONS * ss;
    let zz_big = Scalar::from(zz as u64);
    for z_sk in nizk.z_s.iter() {
        if z_sk >= &zz_big {
            return Err(ZkProofChunkingError::InvalidProof);
        }
    }

    let first_move = FirstMoveChunking::new(nizk.y0, nizk.bb.clone(), nizk.cc.clone());
    let second_move = SecondMoveChunking::from(&nizk.z_s, &nizk.dd, &nizk.yy);
    let e = ChunksOracle::new(public_keys, ciphertexts, &first_move).get_all_chunks(n, m);
    let x = second_challenge(&e, &second_move);
    let xpowers = get_xpowers(&x, NUM_ZK_REPETITIONS);
    let g1 = G1Projective::generator();

    let rhs = batch_mul(&g1, &nizk.z_r);
    let lhs: Vec<G1Projective> = {
        let mut lhs = Vec::with_capacity(e.len());
        for (i, e_i) in e.iter().enumerate() {
            let e_ijk_polynomials: Vec<_> = e_i.iter().map(|e_ij| scalar_usize_mult_exp(&xpowers, e_ij)).collect();
            let rj_e_ijk = G1Projective::multi_exp(&ciphertexts.rr, &e_ijk_polynomials);
            lhs.push(rj_e_ijk + &nizk.dd[i + 1]);
        }
        lhs
    };
    if lhs != rhs {
        return Err(ZkProofChunkingError::InvalidProof);
    }

    let lhs = G1Projective::multi_exp(&nizk.bb, &xpowers) + &nizk.dd[0];
    let rhs = g1 * &nizk.z_beta;
    if lhs != rhs {
        return Err(ZkProofChunkingError::InvalidProof);
    }

    let cij_to_eijks: Vec<G1Projective> = (0..NUM_ZK_REPETITIONS)
        .map(|k| {
            let c_ij_s: Vec<_> = ciphertexts.cc.iter().flatten().copied().collect();
            let e_ijk_s: Vec<_> = e.iter().flatten().map(|e_ij| Scalar::from(e_ij[k] as u64)).collect();
            if c_ij_s.len() != m * n || e_ijk_s.len() != m * n {
                return Err(ZkProofChunkingError::InvalidProof);
            }
            Ok(G1Projective::multi_exp(&c_ij_s, &e_ijk_s) + &nizk.cc[k])
        })
        .collect::<Result<Vec<_>, _>>()?;

    let lhs = G1Projective::multi_exp(&cij_to_eijks[..], &xpowers[..]) + &nizk.yy;
    let acc = scalar_mult_exp(&nizk.z_s, &xpowers);
    let rhs = G1Projective::multi_exp(public_keys, &nizk.z_r)
        + G1Projective::multi_exp(&[nizk.y0, g1], &[nizk.z_beta, acc]);
    if lhs != rhs {
        return Err(ZkProofChunkingError::InvalidProof);
    }
    Ok(())
}

#[inline]
fn require_eq(actual: usize, expected: usize) -> Result<(), ZkProofChunkingError> {
    if expected != actual { Err(ZkProofChunkingError::InvalidProof) } else { Ok(()) }
}

fn second_challenge(first_challenge: &Vec<Vec<Vec<usize>>>, second_move: &SecondMoveChunking) -> Scalar {
    let mut t = merlin::Transcript::new(NIVSS_DOM_SEP);
    fs_util::append_scalars(&mut t, b"", &second_move.z_s);
    fs_util::append_g1_vector(&mut t, b"", &second_move.dd);
    fs_util::append_g1_point(&mut t, b"", &second_move.yy);
    for x in first_challenge.iter() {
        for y in x.iter() {
            for &z in y.iter() {
                t.append_u64(b"", z as u64);
            }
        }
    }
    let mut buf = [0u8; 64];
    t.challenge_bytes(b"challenge_c", &mut buf);
    hash_to_scalar(buf.as_slice(), b"")
}

struct ChunksOracle {
    rng: ChaCha20Rng,
}

impl ChunksOracle {
    fn new(public_keys: &[G1Projective], cxts: &CiphertextChunks, first_move: &FirstMoveChunking) -> Self {
        let mut t = merlin::Transcript::new(NIVSS_DOM_SEP);
        t.append_encryption_keys(&public_keys.to_vec());
        t.append_chunks_ciphertext(cxts);
        fs_util::append_g1_point(&mut t, b"", &first_move.y0);
        fs_util::append_g1_vector(&mut t, b"", &first_move.bb);
        fs_util::append_g1_vector(&mut t, b"", &first_move.cc);

        let mut buf = [0u8; 32];
        t.challenge_bytes(b"label", &mut buf);
        Self { rng: ChaCha20Rng::from_seed(buf) }
    }

    fn getbyte(&mut self) -> u8 {
        let mut b: [u8; 1] = [0; 1];
        self.rng.fill_bytes(&mut b);
        b[0]
    }

    fn get_chunk(&mut self) -> usize {
        CHALLENGE_MASK & (0..CHALLENGE_BYTES).fold(0, |state, _| (state << 8) | (self.getbyte() as usize))
    }

    fn get_all_chunks(&mut self, n: usize, m: usize) -> Vec<Vec<Vec<usize>>> {
        (0..n)
            .map(|_| (0..m).map(|_| (0..NUM_ZK_REPETITIONS).map(|_| self.get_chunk()).collect()).collect())
            .collect()
    }
}

fn random_within_range<R: RngCore>(rng: &mut R, n: u64) -> Scalar {
    let die = Uniform::from(0..n);
    let val = die.sample(rng);
    Scalar::from(val)
}
