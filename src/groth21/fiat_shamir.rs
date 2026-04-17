use blstrs::G1Projective;

use super::encryption::CiphertextChunks;
use super::fs_util;

pub const NIVSS_DOM_SEP: &[u8; 13] = b"NIVSS_DOM_SEP";

pub trait FiatShamirProtocol {
    fn append_encryption_keys(&mut self, eks: &Vec<G1Projective>);
    fn append_chunks_ciphertext(&mut self, ctxt: &CiphertextChunks);
}

impl FiatShamirProtocol for merlin::Transcript {
    fn append_encryption_keys(&mut self, eks: &Vec<G1Projective>) {
        fs_util::append_g1_vector(self, b"encryption-keys", eks);
    }

    fn append_chunks_ciphertext(&mut self, ctxts: &CiphertextChunks) {
        fs_util::append_g1_vector(self, b"", &ctxts.rr);
        ctxts.cc.iter().for_each(|ctxt| fs_util::append_g1_vector(self, b"", &ctxt.to_vec()));
    }
}
