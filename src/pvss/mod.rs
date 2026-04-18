//! Abstract interface shared by all PVSS schemes in this crate.

mod config;
mod secret;

pub use config::SharingConfiguration;
pub use secret::{InputSecret, Share};

use rand_core::{CryptoRng, RngCore};
use serde::{de::DeserializeOwned, Serialize};

/// A publicly-verifiable secret sharing scheme.
///
/// The four pieces the scheme must expose are deliberately separated into associated types:
/// the CRS / [`PublicParameters`](PvssScheme::PublicParameters), the dealer's
/// [`InputSecret`](PvssScheme::InputSecret), the [`Transcript`](PvssScheme::Transcript) produced
/// by [`deal`](PvssScheme::deal) and consumed by [`verify`](PvssScheme::verify), and the
/// [`Share`](PvssScheme::Share) recovered by [`decrypt_share`](PvssScheme::decrypt_share).
///
/// Share decryption is split in two to keep expensive one-time preprocessing off the
/// per-share critical path:
///
/// 1. [`decryptor`](PvssScheme::decryptor) — precompute any receiver-side state that
///    depends only on the CRS (e.g. discrete-log tables). Call once per
///    `PublicParameters`.
/// 2. [`decrypt_share`](PvssScheme::decrypt_share) — reuse the precomputed state to
///    recover one receiver's share.
pub trait PvssScheme {
    /// Common reference string: curve points, receivers' encryption keys, threshold, etc.
    type PublicParameters;

    /// Private input the dealer hands to [`deal`](PvssScheme::deal).
    type InputSecret;

    /// The publicly-verifiable output of [`deal`](PvssScheme::deal).
    type Transcript: Serialize + DeserializeOwned;

    /// A receiver's decrypted share.
    type Share;

    /// A receiver's decryption key.
    type DecryptionKey;

    /// Precomputed receiver-side state. Potentially expensive to build but reused
    /// across all share decryptions under the same `PublicParameters`.
    type Decryptor;

    /// Produce a transcript that publicly commits to `secret` under `pp`.
    fn deal<R: RngCore + CryptoRng>(
        pp: &Self::PublicParameters,
        secret: &Self::InputSecret,
        rng: &mut R,
    ) -> Self::Transcript;

    /// Check that `transcript` is a well-formed dealing under `pp`.
    fn verify(pp: &Self::PublicParameters, transcript: &Self::Transcript) -> bool;

    /// Build the receiver-side precomputed state from the CRS. Call once.
    fn decryptor(pp: &Self::PublicParameters) -> Self::Decryptor;

    /// Decrypt the share of the receiver at `index` using its `decryption_key`.
    fn decrypt_share(
        decryptor: &Self::Decryptor,
        transcript: &Self::Transcript,
        decryption_key: &Self::DecryptionKey,
        index: usize,
    ) -> Self::Share;
}
