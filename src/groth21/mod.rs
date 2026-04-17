//! The Groth21 publicly-verifiable secret sharing scheme over BLS12-381.
//!
//! This module exposes [`Groth21`], a marker type implementing
//! [`PvssScheme`](crate::pvss::PvssScheme), together with its CRS
//! ([`PublicParameters`]) and [`Transcript`].

mod chunking;
mod dealing;
pub mod dlog_recovery;
mod encryption;
mod fiat_shamir;
mod fs_util;
mod nizk_chunking;
mod nizk_sharing;
mod utils;

use std::ops::Mul;

use blstrs::{G1Projective, G2Projective, Scalar};
use ff::Field;
use group::Group;
use rand_core::{CryptoRng, RngCore};
use serde::{Deserialize, Serialize};

use crate::math::fft::fft;
use crate::math::scalar::random_scalars;
use crate::pvss::{InputSecret, PvssScheme, Share, SharingConfiguration};

pub use chunking::NUM_CHUNKS;
pub use dealing::{create_dealing, verify_dealing};
pub use dlog_recovery::{BabyStepGiantStep, CheatingDealerDlogSolver};
pub use encryption::{CiphertextChunks, dec_chunks};
pub use nizk_chunking::ProofChunking;
pub use nizk_sharing::ProofSharing;

/// The Groth21 CRS / public parameters.
///
/// Holds the Pedersen commitment bases (in $\mathbb{G}_1$ and $\mathbb{G}_2$), the receivers'
/// ElGamal encryption keys, and the sharing configuration (threshold + number of players).
#[derive(Clone)]
pub struct PublicParameters {
    pub(crate) bases_g1: [G1Projective; 2],
    pub(crate) bases_g2: [G2Projective; 2],
    pub(crate) encryption_keys: Vec<G1Projective>,
    pub(crate) sharing_config: SharingConfiguration,
}

impl PublicParameters {
    /// Build a CRS. The commitment base `g1` is $\mathbb{G}_1$'s generator; the randomness base
    /// `h1` (and its $\mathbb{G}_2$ counterpart) are sampled with `hash_to_curve(seed, dst, _)`.
    pub fn new(sharing_config: SharingConfiguration, encryption_keys: Vec<G1Projective>, seed: &[u8], dst: &[u8]) -> Self {
        assert_eq!(encryption_keys.len(), sharing_config.get_total_num_players());
        let g1 = G1Projective::generator();
        let h1 = G1Projective::hash_to_curve(seed, dst, b"h_g1");
        let g2 = G2Projective::generator();
        let h2 = G2Projective::hash_to_curve(seed, dst, b"h_g2");
        PublicParameters {
            bases_g1: [g1, h1],
            bases_g2: [g2, h2],
            encryption_keys,
            sharing_config,
        }
    }

    pub fn g1_bases(&self) -> &[G1Projective; 2] { &self.bases_g1 }

    pub fn g2_bases(&self) -> &[G2Projective; 2] { &self.bases_g2 }

    pub fn encryption_keys(&self) -> &[G1Projective] { &self.encryption_keys }

    pub fn sharing_config(&self) -> &SharingConfiguration { &self.sharing_config }

    pub fn n(&self) -> usize { self.sharing_config.get_total_num_players() }

    pub fn t(&self) -> usize { self.sharing_config.get_threshold() }

    /// The randomness base $h_1 \in \mathbb{G}_1$ used in Pedersen commitments.
    pub fn h1(&self) -> G1Projective { self.bases_g1[1] }
}

/// The Groth21 transcript: Pedersen commitments to every player's share (in both $\mathbb{G}_1$
/// and $\mathbb{G}_2$) plus a verifiable-encryption subtranscript containing the chunked
/// ElGamal ciphertext and the two NIZK proofs (chunking and sharing).
#[allow(non_snake_case)]
#[derive(Clone, Serialize, Deserialize)]
pub struct Transcript {
    pub coms_g1: Vec<G1Projective>,
    pub coms_g2: Vec<G2Projective>,
    pub ciphertext: CiphertextChunks,
    pub chunk_proof: ProofChunking,
    pub r_bb: G1Projective,
    pub enc_rr: Vec<G1Projective>,
    pub share_proof: ProofSharing,
}

/// Marker type implementing [`PvssScheme`] for Groth21.
pub struct Groth21;

impl PvssScheme for Groth21 {
    type PublicParameters = PublicParameters;
    type InputSecret = InputSecret;
    type Transcript = Transcript;
    type Share = Share;
    type DecryptionKey = Scalar;

    fn deal<R: RngCore + CryptoRng>(pp: &PublicParameters, secret: &InputSecret, rng: &mut R) -> Transcript {
        let sc = &pp.sharing_config;
        assert_eq!(secret.polynomial().len(), sc.get_threshold());
        assert_eq!(secret.masking_polynomial().len(), sc.get_threshold());

        let mut f_evals = fft(secret.polynomial(), sc.get_evaluation_domain());
        f_evals.truncate(sc.get_total_num_players());
        let mut r_evals = fft(secret.masking_polynomial(), sc.get_evaluation_domain());
        r_evals.truncate(sc.get_total_num_players());

        let n = sc.get_total_num_players();
        let mut coms_g1: Vec<G1Projective> = Vec::with_capacity(n);
        let mut coms_g2: Vec<G2Projective> = Vec::with_capacity(n);
        for i in 0..n {
            let scalars = [f_evals[i], r_evals[i]];
            coms_g1.push(G1Projective::multi_exp(&pp.bases_g1, &scalars));
            coms_g2.push(G2Projective::multi_exp(&pp.bases_g2, &scalars));
        }

        let (ciphertext, r_bb, enc_rr, chunk_proof, share_proof) = create_dealing(
            &pp.h1(),
            &coms_g1,
            &pp.encryption_keys,
            &f_evals,
            &r_evals,
            rng,
        );

        Transcript { coms_g1, coms_g2, ciphertext, chunk_proof, r_bb, enc_rr, share_proof }
    }

    fn verify(pp: &PublicParameters, t: &Transcript) -> bool {
        if t.coms_g1.len() != pp.n() || t.coms_g2.len() != pp.n() {
            return false;
        }
        if t.enc_rr.len() != pp.n() {
            return false;
        }
        verify_dealing(
            &pp.h1(),
            &t.coms_g1,
            &pp.encryption_keys,
            &t.ciphertext,
            &t.chunk_proof,
            &t.r_bb,
            &t.enc_rr,
            &t.share_proof,
        )
    }

    fn decrypt_share(transcript: &Transcript, dk: &Scalar, index: usize) -> Share {
        let secret = dec_chunks(&transcript.ciphertext, *dk, index);
        Share::new(secret, Scalar::ZERO)
    }
}

/// Convenience: sample a set of $n$ (decryption-key, encryption-key) pairs.
pub fn random_encryption_keys<R: RngCore + CryptoRng>(n: usize, rng: &mut R) -> (Vec<Scalar>, Vec<G1Projective>) {
    let dks = random_scalars(n, rng);
    let g = G1Projective::generator();
    let eks = dks.iter().map(|x| g.mul(x)).collect();
    (dks, eks)
}

/// Low-degree test over the $\mathbb{G}_1$ commitments: verifies that `coms_g1` interpolates a
/// polynomial of degree $< t$.
pub fn low_deg_test<R: RngCore + CryptoRng>(coms: &[G1Projective], sc: &SharingConfiguration, rng: &mut R) -> bool {
    if sc.get_threshold() == sc.get_total_num_players() {
        return true;
    }
    let batch_dom = crate::math::evaluation_domain::BatchEvaluationDomain::new(sc.get_total_num_players());
    let vf = dual_code_word(sc.get_threshold() - 1, &batch_dom, sc.get_total_num_players(), rng);
    let ip = G1Projective::multi_exp(coms, vf.as_ref());
    ip.eq(&G1Projective::identity())
}

fn dual_code_word<R: RngCore + CryptoRng>(
    deg: usize,
    batch_dom: &crate::math::evaluation_domain::BatchEvaluationDomain,
    n: usize,
    rng: &mut R,
) -> Vec<Scalar> {
    let mut f = random_scalars(n - deg - 2, rng);
    let dom = batch_dom.get_subdomain(n);
    crate::math::fft::fft_assign(&mut f, &dom);
    f.truncate(n);
    let v = crate::math::lagrange::all_lagrange_denominators(batch_dom, n);
    f.iter().zip(v.iter()).map(|(a, b)| a.mul(b)).collect()
}

/// Reconstruct $(f(0), r(0))$ from any $\ge t$ shares.
pub fn reconstruct(shares: &[Share], players: &[usize], n: usize) -> (Scalar, Scalar) {
    let batch_dom = crate::math::evaluation_domain::BatchEvaluationDomain::new(n);
    let lagr = crate::math::lagrange::lagrange_coefficients_at_zero(&batch_dom, players);
    let mut s = Scalar::ZERO;
    let mut r = Scalar::ZERO;
    for i in 0..shares.len() {
        s += lagr[i].mul(shares[i].share());
        r += lagr[i].mul(shares[i].randomness());
    }
    (s, r)
}
