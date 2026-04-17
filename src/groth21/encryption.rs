#![allow(clippy::needless_range_loop)]

use std::ops::Mul;

use blstrs::{G1Projective, Scalar};
use group::Group;
use rand_core::{CryptoRng, RngCore};
use serde::{Deserialize, Serialize};

use crate::math::scalar::random_scalars;

use super::chunking::{PlaintextChunks, CHUNK_SIZE, NUM_CHUNKS};
use super::dlog_recovery::CheatingDealerDlogSolver;
use super::nizk_chunking::{prove_chunking, verify_chunking, ChunkingWitness, ProofChunking};
use super::utils::{get_xpowers_at_0, scalar_mult_exp};

#[derive(Clone, Default, Serialize, Deserialize)]
pub struct CiphertextChunks {
    pub(crate) rr: Vec<G1Projective>,
    pub(crate) cc: Vec<[G1Projective; NUM_CHUNKS]>,
}

impl CiphertextChunks {
    pub fn new(rr: Vec<G1Projective>, cc: Vec<[G1Projective; NUM_CHUNKS]>) -> Self {
        CiphertextChunks { rr, cc }
    }
}

pub struct EncryptionWitness {
    pub(crate) r_0: Scalar,
    pub(crate) scalars_r: [Scalar; NUM_CHUNKS],
}

pub fn enc_chunks<R: RngCore + CryptoRng>(
    public_keys: &[G1Projective],
    plaintext_chunks: &Vec<PlaintextChunks>,
    rng: &mut R,
) -> (CiphertextChunks, EncryptionWitness) {
    let receivers = public_keys.len();
    let g1 = G1Projective::generator();

    let r: [Scalar; NUM_CHUNKS] = random_scalars(NUM_CHUNKS, rng).try_into().expect("len NUM_CHUNKS");
    let b = Scalar::from(CHUNK_SIZE as u64);
    let bpowers = get_xpowers_at_0(&b, NUM_CHUNKS);
    let r_0 = scalar_mult_exp(&r, &bpowers);

    let rr = r.iter().map(|x| g1.mul(x)).collect();

    let mut cc: Vec<[G1Projective; NUM_CHUNKS]> = Vec::with_capacity(receivers);
    for i in 0..receivers {
        let pk = public_keys[i];
        let ptext = &plaintext_chunks[i];
        let pk_g1_tbl = [pk, g1];
        let chunks = ptext.chunks_as_scalars();

        let mut v = Vec::with_capacity(NUM_CHUNKS);
        for j in 0..NUM_CHUNKS {
            let scalars = [r[j], chunks[j]];
            v.push(G1Projective::multi_exp(&pk_g1_tbl, &scalars));
        }
        let array: [G1Projective; NUM_CHUNKS] = v.try_into().expect("len NUM_CHUNKS");
        cc.push(array);
    }

    (CiphertextChunks::new(rr, cc), EncryptionWitness { r_0, scalars_r: r })
}

pub fn dec_chunks(ctxt: &CiphertextChunks, secret: Scalar, index: usize) -> Scalar {
    let n = ctxt.cc.len();
    let m = ctxt.cc[index].len();

    let cj = &ctxt.cc[index];
    let powers: Vec<G1Projective> = cj.iter().zip(ctxt.rr.iter()).map(|(cc, rr)| cc - rr.mul(secret)).collect();

    let solver = CheatingDealerDlogSolver::new(n, m);
    let mut dlogs: Vec<Scalar> = powers.iter().map(|p| solver.solve(p).expect("dlog in range")).collect();

    dlogs.reverse();
    PlaintextChunks::from_dlogs(&dlogs).recombine_to_scalar()
}

pub fn encrypt_and_prove<R: RngCore + CryptoRng>(
    public_keys: &[G1Projective],
    shares: &[Scalar],
    rng: &mut R,
) -> (CiphertextChunks, ProofChunking, Scalar) {
    let plaintext_chunks: Vec<_> = shares.iter().map(PlaintextChunks::from_scalar).collect();
    let (ciphertext, encryption_witness) = enc_chunks(public_keys, &plaintext_chunks, rng);

    let big_plaintext_chunks: Vec<_> = plaintext_chunks.iter().map(|c| c.chunks_as_scalars()).collect();
    let chunking_witness = ChunkingWitness::new(encryption_witness.scalars_r, big_plaintext_chunks);
    let chunking_proof = prove_chunking(public_keys, &ciphertext, &chunking_witness, rng);

    (ciphertext, chunking_proof, encryption_witness.r_0)
}

pub fn verify_chunk_proofs(
    receiver_keys: &[G1Projective],
    ciphertext: &CiphertextChunks,
    chunking_proof: &ProofChunking,
) -> bool {
    verify_chunking(receiver_keys, ciphertext, chunking_proof).is_ok()
}
