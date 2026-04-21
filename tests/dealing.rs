//! End-to-end test: deal, verify, decrypt, reconstruct.

use blstrs::{G1Projective, Scalar};
use ff::Field;
use rand::seq::IteratorRandom;
use rand::thread_rng;

use e2e_vss::groth21::malicious::{malicious_deal, max_malicious_chunk};
use e2e_vss::groth21::{low_deg_test, random_encryption_keys, reconstruct, Groth21, PublicParameters};
use e2e_vss::math::scalar::random_scalar;
use e2e_vss::pvss::{InputSecret, PvssScheme, SharingConfiguration};

#[test]
fn deal_verify_decrypt_reconstruct() {
    let mut rng = thread_rng();

    let th: usize = 4;
    let deg = 2 * th;
    let n = 3 * th + 1;
    let sc = SharingConfiguration::new(deg + 1, n);

    let (dks, eks) = random_encryption_keys(n, &mut rng);
    let pp = PublicParameters::new(sc.clone(), eks, b"e2e-vss-tests", b"e2e-vss");

    // Use pedersen=false so the recovered share alone (r=0) commits to coms_g1[i].
    let secret = InputSecret::new_random(&sc, false, &mut rng);
    let transcript = Groth21::deal(&pp, &secret, &mut rng);

    assert!(Groth21::verify(&pp, &transcript));

    // Precompute the BSGS table once, reuse across all receivers.
    let decryptor = Groth21::decryptor(&pp);

    let g1_bases = pp.g1_bases();
    let mut all_shares = Vec::with_capacity(n);
    for i in 0..n {
        let share = Groth21::decrypt_share(&decryptor, &transcript, &dks[i], i);
        let com: G1Projective = transcript.coms_g1[i];
        let e_com = G1Projective::multi_exp(g1_bases, share.as_scalars());
        assert!(com.eq(&e_com), "share {i} doesn't match commitment");
        all_shares.push(share);
    }

    assert!(low_deg_test(&transcript.coms_g1, &sc, &mut rng));

    let mut players: Vec<usize> = (0..n).choose_multiple(&mut rng, deg + 1).into_iter().collect();
    players.sort();
    let chosen: Vec<_> = players.iter().map(|&i| all_shares[i]).collect();

    let (recon_s, _recon_r) = reconstruct(&chosen, &players, n);
    // `decrypt_share` only recovers the share value (not the masking r), so we only check `s`.
    assert_eq!(recon_s, secret.secret());
}

#[test]
fn malicious_deal_passes_verification() {
    let mut rng = thread_rng();

    let n: usize = 128;
    let t: usize = 2 * n / 3;
    // Round up so t/n >= 2/3.
    let t = if 3 * t < 2 * n { t + 1 } else { t };
    let sc = SharingConfiguration::new(t, n);

    let (_dks, eks) = random_encryption_keys(n, &mut rng);
    let pp = PublicParameters::new(sc, eks, b"e2e-vss-tests", b"e2e-vss");

    // Simulate a resharing-style scenario where a_0 is fixed by a previous epoch.
    let a_0 = random_scalar(&mut rng);

    // Install the biggest chunk the sigma_k = 0 attack admits.
    let c = max_malicious_chunk(n);

    // Sanity: c should be dramatically larger than the honest chunk bound B-1,
    // otherwise this test isn't exercising anything interesting.
    use e2e_vss::groth21::NUM_CHUNKS;
    let b_minus_1 = (1u64 << (32 / NUM_CHUNKS as u64 * 8)) - 1;
    assert!(c > b_minus_1, "malicious chunk not oversized: c={} <= B-1={}", c, b_minus_1);
    println!("n={} t={} c={} (~2^{:.1}) vs honest B-1={} (~2^{:.1})",
        n, t, c, (c as f64).log2(), b_minus_1, (b_minus_1 as f64).log2());

    let transcript = malicious_deal(&pp, a_0, c, &mut rng);

    assert!(Groth21::verify(&pp, &transcript), "malicious transcript failed verification");

    // Receiver 0 was targeted: f_evals[0] = p(1) = c, so its commitment should
    // open to (c, 0) under (g1, h1).
    let g1_bases = pp.g1_bases();
    let expected_com: G1Projective =
        G1Projective::multi_exp(g1_bases, &[Scalar::from(c), Scalar::ZERO]);
    assert_eq!(transcript.coms_g1[0], expected_com, "receiver 0's commitment should open to (c, 0)");
}
