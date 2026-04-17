//! NIZK proof of correct sharing.
#![allow(clippy::needless_range_loop)]

use std::ops::{Add, Mul};

use blstrs::{G1Projective, Scalar};
use group::Group;
use rand_core::{CryptoRng, RngCore};
use serde::{Deserialize, Serialize};

use crate::math::scalar::{hash_to_scalar, random_scalar};

use super::chunking::{CHUNK_SIZE, NUM_CHUNKS};
use super::encryption::CiphertextChunks;
use super::fiat_shamir::NIVSS_DOM_SEP;
use super::fs_util;
use super::utils::{get_xpowers, get_xpowers_at_0, scalar_mult_exp};

#[derive(Clone, Debug)]
pub struct SharingWitness {
    enc_s: Scalar,
    enc_r: Scalar,
    shares: Vec<Scalar>,
    randomness: Vec<Scalar>,
}

impl SharingWitness {
    pub fn new(enc_s: Scalar, enc_r: Scalar, shares: Vec<Scalar>, randomness: Vec<Scalar>) -> Self {
        Self { enc_s, enc_r, shares, randomness }
    }
}

#[derive(Clone, Serialize, Deserialize)]
pub struct ProofSharing {
    ff: G1Projective,
    aa: G1Projective,
    yy: G1Projective,
    z_s: Scalar,
    z_r: Scalar,
    z_ab: Scalar,
}

pub fn prove_sharing<R: RngCore + CryptoRng>(
    h: &G1Projective,
    commits: &[G1Projective],
    public_keys: &[G1Projective],
    r_aa: &G1Projective,
    enc_ss: &[G1Projective],
    r_bb: &G1Projective,
    enc_rr: &[G1Projective],
    witness: &SharingWitness,
    rng: &mut R,
) -> ProofSharing {
    let n = public_keys.len();

    let x = ShareOracle::new(commits, public_keys, r_aa, enc_ss, r_bb, enc_rr).get_chal();
    let xpowers = get_xpowers(&x, n);

    let s = scalar_mult_exp(&witness.shares, &xpowers);
    let r = scalar_mult_exp(&witness.randomness, &xpowers);

    let pk_mul_xi = G1Projective::multi_exp(public_keys, &xpowers);
    let g1 = G1Projective::generator();

    let alpha = random_scalar(rng);
    let beta = random_scalar(rng);
    let rho = random_scalar(rng);

    let ff = g1.mul(&rho);
    let aa = G1Projective::multi_exp(&[g1, *h], &[alpha, beta]);
    let pk_rho = pk_mul_xi.mul(&rho);
    let yy = pk_rho.add(&aa);

    let x_chal = first_challenge(&x, &ff, &aa, &yy);

    let z_s = s * x_chal + alpha;
    let z_r = r * x_chal + beta;
    let z_ab = (witness.enc_s + witness.enc_r) * x_chal + rho;

    ProofSharing { ff, aa, yy, z_s, z_r, z_ab }
}

fn first_challenge(x: &Scalar, ff: &G1Projective, aa: &G1Projective, yy: &G1Projective) -> Scalar {
    let mut t = merlin::Transcript::new(NIVSS_DOM_SEP);
    fs_util::append_scalar(&mut t, b"", x);
    fs_util::append_g1_point(&mut t, b"", ff);
    fs_util::append_g1_point(&mut t, b"", aa);
    fs_util::append_g1_point(&mut t, b"", yy);

    let mut buf = [0u8; 64];
    t.challenge_bytes(b"challenge_c", &mut buf);
    hash_to_scalar(buf.as_slice(), b"")
}

struct ShareOracle {
    t: merlin::Transcript,
}

impl ShareOracle {
    fn new(
        commits: &[G1Projective],
        public_keys: &[G1Projective],
        aa: &G1Projective,
        enc_ss: &[G1Projective],
        bb: &G1Projective,
        enc_rr: &[G1Projective],
    ) -> Self {
        let mut t = merlin::Transcript::new(NIVSS_DOM_SEP);
        fs_util::append_g1_vector(&mut t, b"", &commits.to_vec());
        fs_util::append_g1_vector(&mut t, b"", &public_keys.to_vec());
        fs_util::append_g1_point(&mut t, b"", aa);
        fs_util::append_g1_vector(&mut t, b"", &enc_ss.to_vec());
        fs_util::append_g1_point(&mut t, b"", bb);
        fs_util::append_g1_vector(&mut t, b"", &enc_rr.to_vec());

        let mut buf = [0u8; 32];
        t.challenge_bytes(b"label", &mut buf);
        Self { t }
    }

    fn get_chal(&mut self) -> Scalar {
        let mut buf = [0u8; 64];
        self.t.challenge_bytes(b"challenge_c", &mut buf);
        hash_to_scalar(buf.as_slice(), b"")
    }
}

pub fn verify_sharing(
    h: &G1Projective,
    commits: &[G1Projective],
    ciphertext: &CiphertextChunks,
    public_keys: &[G1Projective],
    r_bb: &G1Projective,
    enc_rr: &[G1Projective],
    sh_proof: &ProofSharing,
) -> bool {
    let n = commits.len();
    let g = G1Projective::generator();

    let b = Scalar::from(CHUNK_SIZE as u64);
    let bpowers = get_xpowers_at_0(&b, NUM_CHUNKS);
    let r_aa = G1Projective::multi_exp(&ciphertext.rr, &bpowers);
    let enc_ss: Vec<G1Projective> = ciphertext.cc.iter().map(|cc| G1Projective::multi_exp(cc, &bpowers)).collect();

    let x = ShareOracle::new(commits, public_keys, &r_aa, &enc_ss, r_bb, enc_rr).get_chal();
    let xpowers = get_xpowers(&x, n);

    let pk_mul_xi = G1Projective::multi_exp(public_keys, &xpowers);
    let com_mul_xi = G1Projective::multi_exp(commits, &xpowers);
    let ss_mul_xi = G1Projective::multi_exp(&enc_ss, &xpowers);
    let rr_mul_xi = G1Projective::multi_exp(enc_rr, &xpowers);

    let r_aa_bb = r_aa.add(r_bb);
    let c_aa_bb = ss_mul_xi.add(&rr_mul_xi);

    let x_chal = first_challenge(&x, &sh_proof.ff, &sh_proof.aa, &sh_proof.yy);

    let lhs1 = r_aa_bb.mul(&x_chal).add(&sh_proof.ff);
    let rhs1 = g.mul(sh_proof.z_ab);
    if lhs1 != rhs1 {
        return false;
    }

    let lhs2 = com_mul_xi.mul(&x_chal).add(&sh_proof.aa);
    let rhs2 = G1Projective::multi_exp(&[g, *h], &[sh_proof.z_s, sh_proof.z_r]);
    if lhs2 != rhs2 {
        return false;
    }

    let lhs3 = c_aa_bb.mul(&x_chal).add(&sh_proof.yy);
    let rhs3 = G1Projective::multi_exp(&[pk_mul_xi, g, *h], &[sh_proof.z_ab, sh_proof.z_s, sh_proof.z_r]);
    if lhs3 != rhs3 {
        return false;
    }

    true
}
