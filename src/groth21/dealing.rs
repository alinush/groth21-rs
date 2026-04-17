use std::ops::{Add, Mul};

use blstrs::{G1Projective, Scalar};
use group::Group;
use rand_core::{CryptoRng, RngCore};

use crate::math::scalar::random_scalar;

use super::encryption::{encrypt_and_prove, verify_chunk_proofs, CiphertextChunks};
use super::nizk_chunking::ProofChunking;
use super::nizk_sharing::{prove_sharing, verify_sharing, ProofSharing, SharingWitness};

/// Create the Groth21 sub-transcript (everything past the Pedersen commitments): the chunked
/// ElGamal ciphertext plus the chunking and sharing NIZKs.
pub fn create_dealing<R: RngCore + CryptoRng>(
    h: &G1Projective,
    commits: &[G1Projective],
    receiver_keys: &[G1Projective],
    shares: &[Scalar],
    randomness: &[Scalar],
    rng: &mut R,
) -> (CiphertextChunks, G1Projective, Vec<G1Projective>, ProofChunking, ProofSharing) {
    let (ctxt, enc_pf, r_a) = encrypt_and_prove(receiver_keys, shares, rng);

    let g1 = G1Projective::generator();
    let r_b = random_scalar(rng);
    let r_bb = g1.mul(r_b);
    let enc_rr: Vec<G1Projective> = randomness
        .iter()
        .zip(receiver_keys.iter())
        .map(|(r, pk)| h.mul(r).add(pk.mul(&r_b)))
        .collect();

    let enc_ss: Vec<G1Projective> = shares
        .iter()
        .zip(receiver_keys.iter())
        .map(|(s, pk)| g1.mul(s).add(pk.mul(&r_a)))
        .collect();

    let r_aa = g1.mul(&r_a);
    let witness = SharingWitness::new(r_a, r_b, shares.to_vec(), randomness.to_vec());
    let sh_pf = prove_sharing(h, commits, receiver_keys, &r_aa, &enc_ss, &r_bb, &enc_rr, &witness, rng);

    (ctxt, r_bb, enc_rr, enc_pf, sh_pf)
}

pub fn verify_dealing(
    h: &G1Projective,
    commits: &[G1Projective],
    public_keys: &[G1Projective],
    ciphertext: &CiphertextChunks,
    enc_proof: &ProofChunking,
    r_bb: &G1Projective,
    enc_rr: &[G1Projective],
    sh_proof: &ProofSharing,
) -> bool {
    let valid_share = verify_sharing(h, commits, ciphertext, public_keys, r_bb, enc_rr, sh_proof);
    valid_share && verify_chunk_proofs(public_keys, ciphertext, enc_proof)
}
