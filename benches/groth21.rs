use criterion::{criterion_group, criterion_main, measurement::Measurement, BenchmarkGroup, BenchmarkId, Criterion, Throughput};
use rand::thread_rng;

use e2e_vss::groth21::{random_encryption_keys, Groth21, PublicParameters};
use e2e_vss::pvss::{InputSecret, PvssScheme, SharingConfiguration};

fn bench_deal<M: Measurement>(t: usize, n: usize, g: &mut BenchmarkGroup<M>) {
    g.throughput(Throughput::Elements(n as u64));

    let sc = SharingConfiguration::new(t + 1, n);
    let (_, eks) = random_encryption_keys(n, &mut thread_rng());
    let pp = PublicParameters::new(sc.clone(), eks, b"groth21-bench", b"e2e-vss");

    g.bench_function(BenchmarkId::new(format!("deal-{}", t), n), move |b| {
        b.iter_with_setup(
            || {
                let mut rng = thread_rng();
                InputSecret::new_random(&sc, true, &mut rng)
            },
            |s| {
                let mut rng = thread_rng();
                Groth21::deal(&pp, &s, &mut rng)
            },
        )
    });
}

fn bench_verify<M: Measurement>(t: usize, n: usize, g: &mut BenchmarkGroup<M>) {
    g.throughput(Throughput::Elements(n as u64));

    let sc = SharingConfiguration::new(t + 1, n);
    let (_, eks) = random_encryption_keys(n, &mut thread_rng());
    let pp = PublicParameters::new(sc.clone(), eks, b"groth21-bench", b"e2e-vss");

    g.bench_function(BenchmarkId::new(format!("verify-{}", t), n), move |b| {
        b.iter_with_setup(
            || {
                let mut rng = thread_rng();
                let s = InputSecret::new_random(&sc, true, &mut rng);
                Groth21::deal(&pp, &s, &mut rng)
            },
            |trx| {
                assert!(Groth21::verify(&pp, &trx));
            },
        )
    });
}

fn groth21_benches(c: &mut Criterion) {
    let mut group = c.benchmark_group("groth21");
    let ns = [4, 8, 16, 32, 64, 128, 256, 512, 1024];
    let ts = [3, 6, 11, 22, 43, 86,  171, 342, 683];
    for (&t, &n) in ts.iter().zip(ns.iter()) {
        bench_deal(t, n, &mut group);
        bench_verify(t, n, &mut group);
    }
    group.finish();
}

criterion_group!(
    name = benches;
    config = Criterion::default().sample_size(10);
    targets = groth21_benches
);
criterion_main!(benches);
