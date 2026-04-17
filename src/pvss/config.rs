use more_asserts::assert_lt;

use crate::math::evaluation_domain::{BatchEvaluationDomain, EvaluationDomain};

/// Encodes the threshold $t$ and number of players $n$ for a PVSS instance.
#[derive(Clone)]
pub struct SharingConfiguration {
    pub(crate) t: usize,
    pub(crate) n: usize,
    dom: EvaluationDomain,
    batch_dom: BatchEvaluationDomain,
}

impl SharingConfiguration {
    /// $t$-out-of-$n$ configuration: any $\ge t$ shares reconstruct.
    pub fn new(t: usize, n: usize) -> Self {
        let batch_dom = BatchEvaluationDomain::new(n);
        let dom = batch_dom.get_subdomain(n);
        SharingConfiguration { n, t, dom, batch_dom }
    }

    pub fn get_threshold(&self) -> usize { self.t }

    pub fn get_total_num_players(&self) -> usize { self.n }

    pub fn get_evaluation_domain(&self) -> &EvaluationDomain { &self.dom }

    pub fn get_batch_evaluation_domain(&self) -> &BatchEvaluationDomain { &self.batch_dom }
}

/// A player identifier in `[0, n)`.
#[derive(PartialEq, Eq, Clone, Copy)]
pub struct Player {
    pub(crate) id: usize,
}

impl SharingConfiguration {
    pub fn get_player(&self, i: usize) -> Player {
        assert_lt!(i, self.n);
        Player { id: i }
    }
}
