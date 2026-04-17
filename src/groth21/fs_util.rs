use blstrs::{G1Projective, Scalar};

pub(crate) fn append_scalar(t: &mut merlin::Transcript, label: &'static [u8], p: &Scalar) {
    t.append_message(label, p.to_bytes_be().as_slice())
}

pub(crate) fn append_scalars(t: &mut merlin::Transcript, label: &'static [u8], vec: &Vec<Scalar>) {
    t.append_u64(label, vec.len() as u64);
    for p in vec {
        t.append_message(label, p.to_bytes_be().as_slice())
    }
}

pub(crate) fn append_g1_point(t: &mut merlin::Transcript, label: &'static [u8], p: &G1Projective) {
    t.append_message(label, p.to_compressed().as_slice())
}

pub(crate) fn append_g1_vector(t: &mut merlin::Transcript, label: &'static [u8], vec: &Vec<G1Projective>) {
    t.append_u64(label, vec.len() as u64);
    for p in vec {
        t.append_message(b"g1_point", p.to_compressed().as_slice())
    }
}
