use std::ops::{AddAssign, Mul, MulAssign, SubAssign};

use blstrs::Scalar;
use ff::Field;

use super::evaluation_domain::{BatchEvaluationDomain, EvaluationDomain};
use super::fft;

pub fn get_evaluation_dom_size_for_multiplication(f: &Vec<Scalar>, g: &Vec<Scalar>) -> usize {
    (f.len() - 1) + (g.len() - 1) + 1
}

pub fn poly_eval(f: &Vec<Scalar>, x: &Scalar) -> Scalar {
    assert!(!f.is_empty());
    let mut eval = Scalar::ZERO;
    let mut x_i = Scalar::ONE;
    for c_i in f {
        eval += c_i * x_i;
        x_i *= x;
    }
    eval
}

pub fn poly_add_assign(f: &mut Vec<Scalar>, g: &[Scalar]) {
    if g.len() > f.len() {
        f.resize(g.len(), Scalar::ZERO);
    }
    for i in 0..g.len() {
        f[i].add_assign(g[i]);
    }
}

pub fn poly_sub_assign(f: &mut Vec<Scalar>, g: &[Scalar]) {
    if g.len() > f.len() {
        f.resize(g.len(), Scalar::ZERO);
    }
    for i in 0..g.len() {
        f[i].sub_assign(g[i]);
    }
}

pub fn poly_mul_assign_fft_with_dom(f: &mut Vec<Scalar>, g: &mut Vec<Scalar>, dom: &EvaluationDomain) {
    fft::fft_assign(f, dom);
    fft::fft_assign(g, dom);
    for i in 0..dom.N {
        f[i].mul_assign(g[i]);
    }
    fft::ifft_assign(f, dom);
    f.truncate(dom.n);
}

pub fn poly_mul_slow(f: &Vec<Scalar>, g: &Vec<Scalar>) -> Vec<Scalar> {
    assert!(!f.is_empty());
    assert!(!g.is_empty());
    let mut out = vec![Scalar::ZERO; f.len() + g.len() - 1];
    for (i1, a) in f.iter().enumerate() {
        for (i2, b) in g.iter().enumerate() {
            let mut prod = *a;
            prod.mul_assign(b);
            out[i1 + i2].add_assign(&prod);
        }
    }
    out
}

/// $Z(X) = \prod_{a \in S} (X - a)$, using FFT-based multiplication once the sub-products are
/// large enough to benefit from it.
#[allow(non_snake_case)]
pub fn accumulator_poly(S: &[Scalar], batch_dom: &BatchEvaluationDomain, fft_thresh: usize) -> Vec<Scalar> {
    let set_size = S.len();

    if set_size == 0 {
        return vec![];
    } else if set_size == 1 {
        return vec![-S[0], Scalar::ONE];
    } else if set_size == 2 {
        return vec![S[0] * S[1], -(S[0] + S[1]), Scalar::ONE];
    } else if set_size == 3 {
        let s1_add_s2 = S[1] + S[2];
        let s1_mul_s2 = S[1] * S[2];
        let c_0 = -(S[0] * s1_mul_s2);
        let c_1 = S[0] * s1_add_s2 + s1_mul_s2;
        let c_2 = -(S[0] + S[1] + S[2]);
        return vec![c_0, c_1, c_2, Scalar::ONE];
    }

    let m = set_size / 2;
    let mut left_poly = accumulator_poly(&S[0..m], batch_dom, fft_thresh);
    let mut right_poly = accumulator_poly(&S[m..], batch_dom, fft_thresh);

    let dom_size = get_evaluation_dom_size_for_multiplication(&left_poly, &right_poly);
    if dom_size < fft_thresh {
        poly_mul_slow(&left_poly, &right_poly)
    } else {
        poly_mul_assign_fft_with_dom(&mut left_poly, &mut right_poly, &batch_dom.get_subdomain(dom_size));
        left_poly
    }
}

pub fn poly_differentiate(f: &mut Vec<Scalar>) {
    let f_deg = f.len() - 1;
    for i in 0..f_deg {
        f[i] = f[i + 1].mul(Scalar::from((i + 1) as u64));
    }
    f.truncate(f_deg);
}

