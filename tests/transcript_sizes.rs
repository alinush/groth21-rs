//! Prints the serialized size of a Groth21 transcript for several (n, t) configurations.
//!
//! Run with:
//!
//! ```sh
//! cargo test --release --test transcript_sizes -- --ignored --nocapture
//! ```

use rand::thread_rng;

use e2e_vss::groth21::{random_encryption_keys, Groth21, PublicParameters};
use e2e_vss::pvss::{InputSecret, PvssScheme, SharingConfiguration};

#[test]
#[ignore]
fn transcript_sizes() {
    let mut rng = thread_rng();

    let ns = [8, 16, 32, 64, 128, 256];
    let ts = [6, 11, 22, 43, 85, 169];

    println!("\n{:<6} {:<6} {:<15} {:<15}", "n", "t", "size (bytes)", "size (KiB)");
    println!("{}", "-".repeat(45));

    for (&n, &t) in ns.iter().zip(ts.iter()) {
        let sc = SharingConfiguration::new(t + 1, n);
        let (_, eks) = random_encryption_keys(n, &mut rng);
        let pp = PublicParameters::new(sc.clone(), eks, b"e2e-vss-sizes", b"e2e-vss");
        let secret = InputSecret::new_random(&sc, true, &mut rng);

        let trx = Groth21::deal(&pp, &secret, &mut rng);
        let size = bincode::serialize(&trx).unwrap().len();

        println!("{:<6} {:<6} {:<15} {:.2}", n, t, size, size as f64 / 1024.0);
    }
}
