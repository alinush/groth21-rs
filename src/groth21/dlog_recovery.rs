//! Baby-step giant-step discrete log solver over $\mathbb{G}_1$ with base $g$ = the generator.
//!
//! Solving is performed using only group additions and hash-map lookups — never an EC
//! scalar multiplication, in setup or in `solve`.
//!
//! # Design
//!
//! The baby-step table straddles zero: it stores `i·g ↦ i` for every `i ∈ [-k, k]`,
//! so both positive and negative small dlogs are recognised directly. A giant step is
//! `m·g` with `m = 2k + 1`, chosen so `m ≈ √(2·n_range + 1)`. A single [`solve`] call
//! walks two symmetric cursors out from the target (one subtracting, one adding
//! `giant_step`) until either cursor lands on a baby entry, or we exceed the bound on
//! `|j|`. This covers the full signed range `[-n_range, n_range]` in a single pass and
//! does at most `√(2·n_range + 1)` group additions — about `√2 ≈ 1.41×` faster in the
//! worst case than two one-sided scans of range `[0, n_range)`.

use std::collections::HashMap;

use blstrs::{G1Projective, Scalar};
use ff::Field;
use group::Group;

use crate::math::scalar::G1_PROJ_NUM_BYTES;

use super::chunking::{CHUNK_SIZE, NUM_CHUNKS};
use super::nizk_chunking::{CHALLENGE_BITS, NUM_ZK_REPETITIONS};

/// Pick `m` for a BSGS targeting a batch of `batch_size` solves. Returns an odd value.
fn auto_m(max_abs: u64, batch_size: u64) -> u64 {
    let range_size = 2u64.saturating_mul(max_abs).saturating_add(1);
    let f = (batch_size.max(1) as f64) * (range_size as f64);
    let mut m = f.sqrt().ceil() as u64;
    if m < 1 { m = 1; }
    if m % 2 == 0 { m += 1; }
    m
}

/// Baby-step giant-step solver for $\log_g T$ when $T = g^x$ with
/// $x \in [-\mathrm{max\_abs}, \mathrm{max\_abs}]$.
pub struct BabyStepGiantStep {
    /// `i·g ↦ i` for every `i ∈ [-k, k]`. Size `2k + 1 = m`.
    table: HashMap<[u8; G1_PROJ_NUM_BYTES], i64>,
    /// `m·g`, i.e. one giant step.
    giant_step: G1Projective,
    /// The baby-step size `m = 2k + 1`.
    m: i64,
    /// Maximum giant-step index to try in each direction. Iteration range is
    /// `j ∈ [-max_j, max_j]`, enough to cover `[-max_abs, max_abs]`.
    max_j: i64,
    /// The promised absolute bound on the returned dlog.
    max_abs: i64,
}

impl BabyStepGiantStep {
    /// Build a BSGS table sized for a single query: `m ≈ √(2·max_abs + 1)`. Amortized
    /// work across `k` solves is `O(k·√(max_abs))`.
    pub fn new(max_abs: u64) -> Self {
        Self::with_m_hint(max_abs, auto_m(max_abs, 1))
    }

    /// Build a BSGS table sized for a *batch* of `batch_size` solves over the same range.
    /// Picks `m ≈ √(batch_size · (2·max_abs + 1))`, which minimizes `setup + batch_size ·
    /// giant_steps` — total work `O(√(batch_size · max_abs))` regardless of how many of
    /// those solves fire. Setup is larger (more memory), so caller should reuse the same
    /// table across all the queries in the batch.
    pub fn new_batched(max_abs: u64, batch_size: u64) -> Self {
        Self::with_m_hint(max_abs, auto_m(max_abs, batch_size))
    }

    /// Build with a caller-specified baby-table size `m_hint` (will be rounded up to the
    /// next odd number). Useful to cap memory.
    pub fn with_m_hint(max_abs: u64, m_hint: u64) -> Self {
        let mut m = m_hint.max(1);
        if m % 2 == 0 { m += 1; }
        let k = (m - 1) / 2;

        // Need max_j·m + k ≥ max_abs so covered range [-max_j·m - k, max_j·m + k] ⊇ [-max_abs, max_abs].
        let max_j = if max_abs <= k { 0 } else { (max_abs - k + m - 1) / m };

        let g = G1Projective::generator();
        let mut table = HashMap::with_capacity(m as usize);

        let mut pos = G1Projective::identity();
        let mut neg = G1Projective::identity();
        table.insert(pos.to_compressed(), 0i64);
        for i in 1..=(k as i64) {
            pos += g;
            neg -= g;
            table.insert(pos.to_compressed(), i);
            table.insert(neg.to_compressed(), -i);
        }
        // `pos` is k·g. Giant step is m·g = (2k+1)·g = 2·(k·g) + g — two group additions.
        let giant_step = pos + pos + g;

        Self { table, giant_step, m: m as i64, max_j: max_j as i64, max_abs: max_abs as i64 }
    }

    /// The actual baby-table size `m`.
    pub fn table_size(&self) -> u64 { self.m as u64 }

    /// Upper bound on the number of giant steps `solve` will take per call.
    pub fn max_giant_steps(&self) -> u64 { self.max_j as u64 }

    /// Find `x ∈ [-max_abs, max_abs]` with `g^x = tgt`, or `None`. At most
    /// `2·max_j ≈ √(2·max_abs + 1)` group additions and hash lookups; no scalar
    /// multiplications.
    pub fn solve(&self, tgt: &G1Projective) -> Option<i64> {
        let in_range = |x: i64| if x.abs() <= self.max_abs { Some(x) } else { None };
        // j = 0: is `tgt` itself in the baby table?
        if let Some(&i) = self.table.get(&tgt.to_compressed()) {
            return in_range(i);
        }
        // Walk two cursors: `up` looks for positive dlogs (x ≈ +j·m),
        //                   `down` looks for negative dlogs (x ≈ -j·m).
        let mut up = *tgt;
        let mut down = *tgt;
        for j in 1..=self.max_j {
            up -= self.giant_step;
            down += self.giant_step;
            if let Some(&i) = self.table.get(&up.to_compressed()) {
                return in_range(j * self.m + i);
            }
            if let Some(&i) = self.table.get(&down.to_compressed()) {
                return in_range(-j * self.m + i);
            }
        }
        None
    }
}

/// Solves for a chunk's discrete log when the dealer may be cheating.
///
/// Follows the Groth21 §6.5 trick: the chunking proof guarantees that for some
/// $\delta \in [1, E)$, $\delta \cdot x$ falls into $[-(Z-1), Z-1]$. We iterate $\delta$
/// upward, solving the discrete log of $g^{\delta x} = \delta \cdot T$ with BSGS until a
/// match is found, then divide by $\delta$ in the scalar field.
pub struct CheatingDealerDlogSolver {
    bsgs: BabyStepGiantStep,
    scale_range: u64,
}

impl CheatingDealerDlogSolver {
    /// Build a solver sized for **one full share decryption**: the baby-step table
    /// is picked to amortize across `m · (E - 1)` BSGS queries (the worst case for
    /// `dec_chunks`), making total batch work `O(√(m·(E-1)·Z))` instead of the naive
    /// `m·(E-1)·√Z`. Setup is expensive — **build once, reuse across many shares**.
    pub fn new(n: usize, m: usize) -> Self {
        let scale_range: u64 = 1 << CHALLENGE_BITS;
        let ss = (n as u64) * (m as u64) * ((CHUNK_SIZE - 1) as u64) * (scale_range - 1);
        let zz = 2 * (NUM_ZK_REPETITIONS as u64) * ss;
        let batch_size = (m as u64) * (scale_range - 1);
        Self {
            bsgs: BabyStepGiantStep::new_batched(zz - 1, batch_size),
            scale_range,
        }
    }

    /// Build with a single-query BSGS table (baby table ≈ √Z). Cheaper setup, but
    /// slower for cheater share decryption. Useful for tests / small-batch use cases.
    pub fn new_unbatched(n: usize, m: usize) -> Self {
        let scale_range: u64 = 1 << CHALLENGE_BITS;
        let ss = (n as u64) * (m as u64) * ((CHUNK_SIZE - 1) as u64) * (scale_range - 1);
        let zz = 2 * (NUM_ZK_REPETITIONS as u64) * ss;
        Self { bsgs: BabyStepGiantStep::new(zz - 1), scale_range }
    }

    /// Build a batched BSGS table sized for **best-case** (δ = 1) decryption
    /// of a whole share: the table covers the full signed soundness range
    /// `[-(Z-1), Z-1]` — because the receiver can't distinguish honest chunks
    /// from approximately-small cheating chunks — but is batched for only
    /// `k = m = NUM_CHUNKS` queries per share (one per chunk, no δ iteration).
    /// Table size `≈ √(m·(2Z-1))`, much smaller than the full
    /// `m·(E-1)`-batched table used by cheater decryption.
    pub fn new_best_case(n_players: usize) -> Self {
        let scale_range: u64 = 1 << CHALLENGE_BITS;
        let n = n_players as u64;
        let m = NUM_CHUNKS as u64;
        let ss = n * m * ((CHUNK_SIZE - 1) as u64) * (scale_range - 1);
        let zz = 2 * (NUM_ZK_REPETITIONS as u64) * ss;
        Self {
            bsgs: BabyStepGiantStep::new_batched(zz - 1, m),
            scale_range,
        }
    }

    pub fn bsgs(&self) -> &BabyStepGiantStep { &self.bsgs }

    /// Returns $x$ with $g^x = \text{target}$, or `None` if no admissible $x$ is found.
    pub fn solve(&self, target: &G1Projective) -> Option<Scalar> {
        let mut target_power = G1Projective::identity();
        for delta in 1..self.scale_range {
            target_power += target;
            if let Some(scaled) = self.bsgs.solve(&target_power) {
                let inv_delta = Scalar::from(delta).invert().unwrap();
                let scaled_scalar = if scaled >= 0 {
                    Scalar::from(scaled as u64)
                } else {
                    -Scalar::from((-scaled) as u64)
                };
                return Some(scaled_scalar * inv_delta);
            }
        }
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::ops::Mul;

    #[test]
    fn bsgs_recovers_positive_dlog() {
        let max_abs = 1u64 << 12;
        let bsgs = BabyStepGiantStep::new(max_abs);
        let g = G1Projective::generator();
        for x in [0i64, 1, 2, 7, 63, 64, 127, 128, 255, 1000, 4095, 4096] {
            let tgt = g.mul(Scalar::from(x as u64));
            assert_eq!(bsgs.solve(&tgt), Some(x), "failed for x = {x}");
        }
    }

    #[test]
    fn bsgs_recovers_negative_dlog() {
        let max_abs = 1u64 << 12;
        let bsgs = BabyStepGiantStep::new(max_abs);
        let g = G1Projective::generator();
        for x in [-4096i64, -4095, -1000, -128, -1] {
            let tgt = g.mul(-Scalar::from((-x) as u64));
            assert_eq!(bsgs.solve(&tgt), Some(x), "failed for x = {x}");
        }
    }

    #[test]
    fn bsgs_out_of_range_returns_none() {
        let max_abs = 1u64 << 10;
        let bsgs = BabyStepGiantStep::new(max_abs);
        let g = G1Projective::generator();
        let tgt_pos = g.mul(Scalar::from(max_abs + 5));
        assert_eq!(bsgs.solve(&tgt_pos), None);
        let tgt_neg = g.mul(-Scalar::from(max_abs + 5));
        assert_eq!(bsgs.solve(&tgt_neg), None);
    }
}
