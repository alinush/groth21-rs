//! End-to-end test: deal, verify, decrypt, reconstruct.

use blstrs::G1Projective;
use rand::seq::IteratorRandom;
use rand::thread_rng;

use e2e_vss::groth21::{low_deg_test, random_encryption_keys, reconstruct, Groth21, PublicParameters};
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

    // Each receiver's share should match the committed evaluation.
    let g1_bases = pp.g1_bases();
    let mut all_shares = Vec::with_capacity(n);
    for i in 0..n {
        let share = Groth21::decrypt_share(&transcript, &dks[i], i);
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
