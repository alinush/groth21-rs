use blstrs::Scalar;
use ff::Field;
use rand_core::{CryptoRng, RngCore};
use serde::{Deserialize, Serialize};

use crate::math::scalar::{random_scalar, random_scalars};

use super::config::SharingConfiguration;

/// The dealer's private input: a polynomial `f` (with $f(0) = a$) and, optionally, a random
/// masking polynomial `r` used by Pedersen-based schemes.
#[derive(Clone, PartialEq)]
pub struct InputSecret {
    a: Scalar,
    f: Vec<Scalar>,
    r: Vec<Scalar>,
}

impl InputSecret {
    /// Samples a random degree-$(t-1)$ polynomial `f` with `f(0) = a`. If `pedersen` is true,
    /// also samples the random masking polynomial `r`; otherwise `r` is all zeros.
    pub fn new_random<R: RngCore + CryptoRng>(sc: &SharingConfiguration, pedersen: bool, rng: &mut R) -> Self {
        let a = random_scalar(rng);
        let mut f = random_scalars(sc.t, rng);
        let r = if pedersen { random_scalars(sc.t, rng) } else { vec![Scalar::ZERO; sc.t] };
        f[0] = a;
        InputSecret { a, f, r }
    }

    pub fn secret(&self) -> Scalar { self.a }

    pub fn polynomial(&self) -> &Vec<Scalar> { &self.f }

    pub fn masking_polynomial(&self) -> &Vec<Scalar> { &self.r }

    pub fn masking_constant(&self) -> Scalar { self.r[0] }
}

/// A pair `(share, randomness)` giving the evaluation of the dealt polynomials at one point.
#[derive(Clone, Copy, Debug, Serialize, Deserialize, Default, PartialEq)]
pub struct Share {
    share: [Scalar; 2],
}

impl Share {
    pub fn new(share: Scalar, randomness: Scalar) -> Self {
        Share { share: [share, randomness] }
    }

    pub fn share(&self) -> Scalar { self.share[0] }

    pub fn randomness(&self) -> Scalar { self.share[1] }

    pub fn as_scalars(&self) -> &[Scalar; 2] { &self.share }
}
