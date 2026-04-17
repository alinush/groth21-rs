use std::ops::Mul;

use blstrs::Scalar;
use ff::BatchInvert;
use more_asserts::{assert_gt, debug_assert_le};

use super::evaluation_domain::BatchEvaluationDomain;
use super::fft::{fft, fft_assign};
use super::polynomials::{accumulator_poly, poly_differentiate, poly_mul_slow};

const FFT_THRESH: usize = 64;

/// Returns the $|T|$ Lagrange coefficients $\ell_i(0)$ for the interpolating set
/// $T = \{\omega^{t_1}, \ldots, \omega^{t_{|T|}}\}$.
#[allow(non_snake_case)]
pub fn lagrange_coefficients_at_zero(dom: &BatchEvaluationDomain, T: &[usize]) -> Vec<Scalar> {
    let N = dom.N();
    let t = T.len();
    assert_gt!(N, 1);
    debug_assert_le!(t, N);

    let mut Z = accumulator_poly_helper(dom, T);
    let omegas = dom.get_all_roots_of_unity();

    let Z_i_at_0 = compute_numerators_at_zero(omegas, T, &Z[0]);
    poly_differentiate(&mut Z);
    fft_assign(&mut Z, &dom.get_subdomain(N));

    let mut denominators = Vec::with_capacity(T.len());
    for i in 0..T.len() {
        denominators.push(Z[T[i]]);
    }
    denominators.batch_invert();

    for i in 0..T.len() {
        Z[i] = Z_i_at_0[i].mul(denominators[i]);
    }

    Z.truncate(t);
    Z
}

#[allow(non_snake_case)]
fn accumulator_poly_helper(dom: &BatchEvaluationDomain, T: &[usize]) -> Vec<Scalar> {
    let omegas = dom.get_all_roots_of_unity();
    let mut set = Vec::with_capacity(T.len());
    for &s in T {
        set.push(omegas[s]);
    }

    if set.len() < dom.N() {
        accumulator_poly(&set, dom, FFT_THRESH)
    } else {
        // Edge case: N-out-of-N interpolation has degree N+1, which is larger than dom.
        let last = set.pop().unwrap();
        let lhs = accumulator_poly(&set, dom, FFT_THRESH);
        let rhs = accumulator_poly(&[last], dom, FFT_THRESH);
        poly_mul_slow(&rhs, &lhs)
    }
}

#[allow(non_snake_case)]
fn compute_numerators_at_zero(omegas: &Vec<Scalar>, ids: &[usize], Z_0: &Scalar) -> Vec<Scalar> {
    let N = omegas.len();
    let mut numerators = Vec::with_capacity(ids.len());
    for &i in ids {
        let idx = if N / 2 < i { N + N / 2 - i } else { N / 2 - i };
        numerators.push(Z_0 * omegas[idx]);
    }
    numerators
}

/// Returns $1 / \prod_{j\ne i, j\in[0,n)} (\omega^i - \omega^j)$ for all $i\in[0,n)$.
#[allow(non_snake_case)]
pub fn all_lagrange_denominators(batch_dom: &BatchEvaluationDomain, n: usize) -> Vec<Scalar> {
    let mut A = accumulator_poly_helper(batch_dom, (0..n).collect::<Vec<usize>>().as_slice());
    poly_differentiate(&mut A);
    let mut denoms = fft(&A, &batch_dom.get_subdomain(n));
    denoms.truncate(n);
    denoms.batch_invert();
    denoms
}
