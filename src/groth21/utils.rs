use std::ops::Mul;

use blstrs::{G1Projective, Scalar};
use ff::Field;

pub fn get_xpowers(x: &Scalar, cnt: usize) -> Vec<Scalar> {
    let mut r = Vec::with_capacity(cnt);
    let mut xpow = Scalar::ONE;
    for _ in 0..cnt {
        xpow *= x;
        r.push(xpow);
    }
    r
}

pub fn get_xpowers_at_0(x: &Scalar, cnt: usize) -> Vec<Scalar> {
    let mut r = Vec::with_capacity(cnt);
    let mut xpow = Scalar::ONE;
    for _ in 0..cnt {
        r.push(xpow);
        xpow *= x;
    }
    r
}

pub fn batch_mul(g: &G1Projective, exps: &Vec<Scalar>) -> Vec<G1Projective> {
    exps.iter().map(|x| g.mul(x)).collect()
}

pub fn scalar_mult_exp(lhs: &[Scalar], rhs: &[Scalar]) -> Scalar {
    let terms = std::cmp::min(lhs.len(), rhs.len());
    let mut accum = Scalar::ZERO;
    for i in 0..terms {
        accum += &lhs[i] * &rhs[i];
    }
    accum
}

pub fn scalar_usize_mult_exp(lhs: &[Scalar], rhs: &[usize]) -> Scalar {
    let terms = std::cmp::min(lhs.len(), rhs.len());
    let mut accum = Scalar::ZERO;
    for i in 0..terms {
        accum += &lhs[i] * Scalar::from(rhs[i] as u64);
    }
    accum
}
