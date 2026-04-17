//! A minimal library implementing the Groth21 publicly-verifiable secret sharing scheme.
//!
//! The scheme is exposed behind a small [`PvssScheme`](pvss::PvssScheme) abstraction so that
//! the CRS/public parameters, the dealing algorithm, the transcript, and the verification
//! algorithm are all first-class and cleanly separated.

pub mod math;
pub mod pvss;
pub mod groth21;

pub use pvss::{PvssScheme, SharingConfiguration, InputSecret, Share};
