# e2e-vss

A minimal Rust implementation of the **Groth21** publicly-verifiable secret
sharing scheme over BLS12-381.

The scheme is exposed behind a small `PvssScheme` trait so that the four
conceptual pieces are first-class and cleanly separated:

- the CRS / [`PublicParameters`](src/groth21/mod.rs),
- the [`InputSecret`](src/pvss/secret.rs) fed to the dealer,
- the [`Transcript`](src/groth21/mod.rs) produced by `deal` and consumed by `verify`, and
- the [`Share`](src/pvss/secret.rs) recovered by `decrypt_share`.

## Layout

```
Cargo.toml
src/
  lib.rs
  math/        -- FFT, evaluation domains, Lagrange, polynomial arithmetic
  pvss/        -- PvssScheme trait, SharingConfiguration, InputSecret, Share
  groth21/     -- CRS, dealing, verification, NIZKs, chunked ElGamal
tests/
  dealing.rs          -- end-to-end deal/verify/decrypt/reconstruct
  transcript_sizes.rs -- prints serialized transcript sizes (ignored by default)
benches/
  groth21.rs           -- Criterion benchmark of deal + verify
  run-pvss-benches.sh  -- runs all benches and prints all transcript sizes
```

## Building & testing

```sh
cargo build
cargo test --release
cargo test --release --test transcript_sizes -- --ignored --nocapture
```

## Benchmarking

```sh
./benches/run-pvss-benches.sh
```

This runs every benchmark and then prints the transcript size for each
configuration.
