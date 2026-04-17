use std::ops::MulAssign;

use blstrs::Scalar;
use ff::{Field, PrimeField};
use more_asserts::{assert_gt, assert_le};

#[allow(non_snake_case)]
#[derive(PartialEq, Debug, Clone)]
pub struct EvaluationDomain {
    pub(crate) n: usize,
    pub(crate) N: usize,
    pub(crate) log_N: usize,
    pub(crate) omega: Scalar,
    pub(crate) omega_inverse: Scalar,
    pub(crate) N_inverse: Scalar,
}

#[allow(non_snake_case)]
#[derive(Clone)]
pub struct BatchEvaluationDomain {
    pub(crate) log_N: usize,
    omegas: Vec<Scalar>,
    N_inverses: Vec<Scalar>,
}

#[allow(non_snake_case)]
fn smallest_power_of_2_greater_or_eq_than(n: usize) -> (usize, usize) {
    let mut N = 1;
    let mut log_N: usize = 0;
    while N < n {
        N <<= 1;
        log_N += 1;
    }
    (N, log_N)
}

impl EvaluationDomain {
    #[allow(non_snake_case)]
    pub fn new(n: usize) -> Option<EvaluationDomain> {
        let (N, log_N) = smallest_power_of_2_greater_or_eq_than(n);
        if log_N >= Scalar::S as usize {
            return None;
        }
        let omega = Self::get_Nth_root_of_unity(log_N);
        Some(EvaluationDomain {
            n,
            N,
            log_N,
            omega,
            omega_inverse: omega.invert().unwrap(),
            N_inverse: Scalar::from(N as u64).invert().unwrap(),
        })
    }

    pub fn size(&self) -> usize { self.N }

    #[allow(non_snake_case)]
    fn get_Nth_root_of_unity(log_N: usize) -> Scalar {
        let mut omega = Scalar::ROOT_OF_UNITY;
        for _ in log_N..Scalar::S as usize {
            omega = omega.square();
        }
        omega
    }

    #[allow(non_snake_case)]
    pub fn get_all_powers(&self, n: usize) -> Vec<Scalar> {
        let mut all_powers: Vec<Scalar> = Vec::with_capacity(n);
        let mut omega_i = self.omega;
        for _ in 0..n {
            all_powers.push(omega_i);
            omega_i.mul_assign(self.omega);
        }
        all_powers
    }
}

impl BatchEvaluationDomain {
    #[allow(non_snake_case)]
    pub fn new(n: usize) -> Self {
        let (N, log_N) = smallest_power_of_2_greater_or_eq_than(n);
        let omega = EvaluationDomain::get_Nth_root_of_unity(log_N);

        let mut omegas = Vec::with_capacity(N);
        omegas.push(Scalar::ONE);

        let mut acc = omega;
        for _ in 1..N {
            omegas.push(acc);
            acc *= omega;
        }

        let mut N_inverses = Vec::with_capacity(log_N);
        let mut i = 1u64;
        for _ in 0..=log_N {
            N_inverses.push(Scalar::from(i).invert().unwrap());
            i *= 2;
        }

        BatchEvaluationDomain { log_N, omegas, N_inverses }
    }

    #[allow(non_snake_case)]
    pub fn N(&self) -> usize { self.omegas.len() }

    #[allow(non_snake_case)]
    pub fn get_subdomain(&self, k: usize) -> EvaluationDomain {
        assert_le!(k, self.omegas.len());
        assert_ne!(k, 0);

        let (K, log_K) = smallest_power_of_2_greater_or_eq_than(k);
        assert_gt!(K, 0);

        let K_inverse = self.N_inverses[log_K];

        let mut idx = 1;
        for _ in log_K..self.log_N {
            idx *= 2;
        }

        let N = self.omegas.len();
        let omega = self.omegas[idx % N];
        let omega_inverse = self.omegas[(N - idx) % N];

        EvaluationDomain {
            n: k,
            N: K,
            log_N: log_K,
            omega,
            omega_inverse,
            N_inverse: K_inverse,
        }
    }

    pub fn get_root_of_unity(&self, i: usize) -> Scalar {
        self.omegas[i]
    }

    pub fn get_all_roots_of_unity(&self) -> &Vec<Scalar> {
        self.omegas.as_ref()
    }
}
