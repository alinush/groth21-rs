use blstrs::Scalar;
use zeroize::Zeroize;

use crate::math::scalar::SCALAR_NUM_BYTES;

/// The size of a chunk in bytes. Controlled by the `chunks-8bit` / `chunks-32bit` features.
#[cfg(not(any(feature = "chunks-8bit", feature = "chunks-32bit")))]
pub const CHUNK_BYTES: usize = 2;
#[cfg(feature = "chunks-8bit")]
pub const CHUNK_BYTES: usize = 1;
#[cfg(feature = "chunks-32bit")]
pub const CHUNK_BYTES: usize = 4;

pub const CHUNK_BITS: usize = CHUNK_BYTES * 8;
/// Cardinality of the chunk range.
pub const CHUNK_SIZE: usize = 1 << CHUNK_BITS;

pub type Chunk = isize;

pub(crate) const MESSAGE_BYTES: usize = SCALAR_NUM_BYTES;
pub const NUM_CHUNKS: usize = (MESSAGE_BYTES + CHUNK_BYTES - 1) / CHUNK_BYTES;

#[derive(Clone, Debug, Zeroize)]
pub struct PlaintextChunks {
    pub(crate) chunks: [Chunk; NUM_CHUNKS],
}

impl PlaintextChunks {
    pub fn from_scalar(s: &Scalar) -> Self {
        let bytes = s.to_bytes_be();
        let mut chunks = [0; NUM_CHUNKS];
        for i in 0..NUM_CHUNKS {
            let slice = &bytes[CHUNK_BYTES * i..CHUNK_BYTES * (i + 1)];
            // Big-endian decode of CHUNK_BYTES bytes into an unsigned integer.
            let mut v: u64 = 0;
            for &b in slice {
                v = (v << 8) | b as u64;
            }
            chunks[i] = v as isize;
        }
        chunks.reverse();
        Self { chunks }
    }

    pub fn from_dlogs(dlogs: &[Scalar]) -> Self {
        let chunk_size = Scalar::from(CHUNK_SIZE as u64);
        let mut acc = Scalar::from(0);
        for dlog in dlogs {
            acc *= &chunk_size;
            acc += dlog;
        }
        Self::from_scalar(&acc)
    }

    pub fn chunks_as_scalars(&self) -> [Scalar; NUM_CHUNKS] {
        self.chunks.map(|c| Scalar::from(c as u64))
    }

    pub fn recombine_to_scalar(&self) -> Scalar {
        let mut temp_chunk = self.chunks;
        temp_chunk.reverse();
        let factor = Scalar::from(CHUNK_SIZE as u64);
        let mut acc = Scalar::from(0);
        for chunk in temp_chunk {
            acc *= &factor;
            acc += Scalar::from(chunk as u64);
        }
        acc
    }
}
