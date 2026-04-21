# Claude notes for `e2e-vss`

Minimal single-crate Rust implementation of the **Groth21** publicly-verifiable secret
sharing scheme (BLS12-381, `blstrs`). Structure:

```
Cargo.toml
src/           lib.rs, math/, pvss/, groth21/
tests/         dealing.rs, transcript_sizes.rs
benches/       groth21.rs, worst_case_decrypt.rs, run-pvss-benches.sh
```

## Getting numbers for the blog's "Full benchmarks" table

The blog at `/chunky#full-benchmarks` (post:
`~/repos/alinush.github.io/_posts/2025-11-18-chunky-weighted-pvss-for-field-elements.md`)
reports four per-`(t, n)` numbers for Groth21:

| Column | What to run | What to read |
|--------|-------------|--------------|
| **Transcript size (KiB)** | `RAYON_NUM_THREADS=1 cargo test --release --features chunks-8bit --test transcript_sizes -- --ignored --nocapture` | The `size (KiB)` column in stdout. |
| **Deal (ms)** | `RAYON_NUM_THREADS=1 cargo bench --features chunks-8bit --bench groth21 -- 'deal-'` | Criterion `time:` median. |
| **Verify (ms)** | `RAYON_NUM_THREADS=1 cargo bench --features chunks-8bit --bench groth21 -- 'verify-'` | Criterion `time:` median. |
| **Decrypt share (ms)** | `RAYON_NUM_THREADS=1 cargo bench --features chunks-8bit --bench worst_case_decrypt -- 'share-decrypt-honest'` | Criterion `time:` median. This is the `δ = 1` honest-dealer cost, which is what any NIZK-valid transcript actually hits (see blog's Groth21 notes). |

**`chunks-8bit` vs default.** The blog's current numbers use 8-bit chunks
(`m = 32`, `B = 2^8`). The default (no feature) is 16-bit chunks (`m = 16`,
`B = 2^16`).

**Threading.** The Cargo.toml pins `blst` with `features = ["no-threads"]` so
blst's internal Pippenger MSM thread pool is compiled out. Prepend
`RAYON_NUM_THREADS=1` to every bench invocation for defense-in-depth:

```bash
RAYON_NUM_THREADS=1 cargo bench --features chunks-8bit --bench groth21
```

**One-shot reproduction** of three of the four columns:

```bash
RAYON_NUM_THREADS=1 ./benches/run-pvss-benches.sh --features chunks-8bit
```

This runs `groth21` (deal + verify) and the `transcript_sizes` test, in that
order. The **Decrypt share (ms)** column needs a separate manual invocation
(`cargo bench --bench worst_case_decrypt -- 'share-decrypt-honest'`) — it's
not in the one-shot script because the `worst_case_decrypt` bench's worst-case
half is minutes-per-`n` at `n ≥ 128` and isn't reported in the blog table.

## (t, n) pairs benched

Defined at the top of each bench / test:

```rust
let ns = [4, 8, 16, 32, 64, 128, 256, 512, 1024];
let ts = [3, 6, 11, 22, 43, 86,  171, 342, 683];
```

Three files to keep in sync:

- `benches/groth21.rs` — `deal`, `verify`.
- `benches/worst_case_decrypt.rs` — `share-decrypt-honest`, `share-decrypt-worst`,
  iterates a hardcoded `for &n in &[...]` in two places.
- `tests/transcript_sizes.rs` — `ns`, `ts` arrays.

## Where Criterion stores raw data (useful for plotting)

Criterion dumps everything under `target/criterion/`. Structure:

```
target/criterion/
├── groth21/                        ← group "groth21" (deal + verify)
│   ├── deal-6/8/                   ← BenchmarkId "deal-{t}/{n}"
│   │   ├── new/
│   │   │   ├── benchmark.json      ← {name, throughput}
│   │   │   ├── estimates.json      ← point+CI for mean, median, std_dev, slope
│   │   │   ├── sample.json         ← {iters, times} raw per-sample timings (ns)
│   │   │   └── tukey.json
│   │   ├── base/                   ← previous run (for change detection)
│   │   └── change/                 ← delta vs base
│   ├── verify-6/8/
│   └── …
├── groth21-decrypt/                ← group from worst_case_decrypt.rs
│   ├── share-decrypt-honest/8/
│   │   └── new/estimates.json
│   └── share-decrypt-worst/8/
└── report/                         ← HTML reports (index.html)
```

**For plotting deal/verify/decrypt-share vs n**, the useful file is
`target/criterion/<group>/<bench-id>/new/estimates.json`. Its JSON shape is
(relevant subset):

```json
{
  "mean":       {"point_estimate": <ns>, "confidence_interval": {"lower_bound": …, "upper_bound": …, "confidence_level": …}},
  "median":     {"point_estimate": <ns>, …},
  "std_dev":    {"point_estimate": <ns>, …},
  "slope":      {"point_estimate": <ns>, …}
}
```

All times are in **nanoseconds**. Divide by `1e6` for ms.

Quick extractor (to dump a tsv with `n,t,metric,time_ms`):

```bash
for f in target/criterion/groth21/deal-*/*/new/estimates.json; do
    # path: target/criterion/groth21/deal-<t>/<n>/new/estimates.json
    id=${f#target/criterion/groth21/}
    pair=${id%/new/estimates.json}        # e.g. "deal-6/8"
    op=${pair%%-*}                        # "deal"
    rest=${pair#${op}-}                   # "6/8"
    t=${rest%/*}                          # "6"
    n=${rest#*/}                          # "8"
    median_ns=$(jq '.median.point_estimate' "$f")
    printf "%s\t%s\t%s\t%s\n" "$op" "$n" "$t" "$median_ns"
done
```

Raw per-sample timings live in `sample.json` (array of iter counts + array of
total ns) if you want to bootstrap confidence intervals yourself.

## Caveats when re-benching

- `RAYON_NUM_THREADS=1 cargo bench` requires a release build (criterion handles this).
- Runs mutate `target/criterion/<id>/base` to be the previous run; if you want
  a clean comparison, `rm -rf target/criterion` first.
- The worst-case decrypt bench at `n ≥ 128` takes minutes per `n` because each
  sample is a full `m · (E-1)` BSGS scan over random targets. The honest bench
  is flat ~1.5 ms regardless of `n`.
- Criterion warmups take ~3 s per bench; `run-pvss-benches.sh --features
  chunks-8bit` (deal + verify + transcript sizes only) takes a few minutes.
  Running `worst_case_decrypt` separately adds ~45 min for `n ≤ 256` and grows
  quickly past that.
- `blstrs` (via `blst`) is currently compiled without threads (see `Cargo.toml`
  `blst = { ..., features = ["no-threads"] }`). If you ever remove that, every
  `multi_exp` call will silently start using `num_cpus::get_physical()` threads
  for Pippenger; numbers become unreproducible across machines.
