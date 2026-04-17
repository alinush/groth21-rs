use blstrs::Scalar;
use ff::Field;
use num_bigint::BigUint;
use num_integer::Integer;
use sha3::Digest;

pub const SCALAR_NUM_BYTES: usize = 32;
pub const G1_PROJ_NUM_BYTES: usize = 48;
pub const G2_PROJ_NUM_BYTES: usize = 96;

/// Order of the BLS12-381 scalar field.
const SCALAR_FIELD_ORDER_BE: [u8; 32] = [
    0x73, 0xed, 0xa7, 0x53, 0x29, 0x9d, 0x7d, 0x48,
    0x33, 0x39, 0xd8, 0x08, 0x09, 0xa1, 0xd8, 0x05,
    0x53, 0xbd, 0xa4, 0x02, 0xff, 0xfe, 0x5b, 0xfe,
    0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x01,
];

lazy_static::lazy_static! {
    static ref SCALAR_FIELD_ORDER: BigUint = {
        let r = BigUint::from_bytes_be(&SCALAR_FIELD_ORDER_BE);
        // Paranoid check: -1 mod r == r - 1.
        let minus_one = Scalar::ZERO - Scalar::ONE;
        let max = &r - 1u8;
        assert_eq!(minus_one.to_bytes_le().as_slice(), max.to_bytes_le().as_slice());
        r
    };
}

pub fn random_scalar<R: rand_core::RngCore + rand_core::CryptoRng>(rng: &mut R) -> Scalar {
    Scalar::random(rng)
}

pub fn random_scalars<R: rand_core::RngCore + rand_core::CryptoRng>(n: usize, rng: &mut R) -> Vec<Scalar> {
    (0..n).map(|_| random_scalar(rng)).collect()
}

/// Hashes `msg` into a `Scalar` via SHA3-512(SHA3-512(dst) || msg) mod r.
pub fn hash_to_scalar(msg: &[u8], dst: &[u8]) -> Scalar {
    let mut hasher = sha3::Sha3_512::new();
    hasher.update(dst);
    let dst_hash = hasher.finalize();

    let mut hasher = sha3::Sha3_512::new();
    hasher.update(dst_hash.as_slice());
    hasher.update(msg);
    let bytes = hasher.finalize();

    let bignum = BigUint::from_bytes_le(bytes.as_slice());
    let remainder = bignum.mod_floor(&SCALAR_FIELD_ORDER);
    biguint_to_scalar(&remainder)
}

fn biguint_to_scalar(big_uint: &BigUint) -> Scalar {
    let mut bytes = big_uint.to_bytes_le();
    while bytes.len() < SCALAR_NUM_BYTES {
        bytes.push(0u8);
    }
    let slice: &[u8; SCALAR_NUM_BYTES] = bytes.as_slice().try_into().expect("fits in 32 bytes");
    let opt = Scalar::from_bytes_le(slice);
    if opt.is_some().unwrap_u8() == 1u8 {
        opt.unwrap()
    } else {
        panic!("Deserialization of random BigUint failed.");
    }
}

#[inline]
pub fn is_power_of_two(n: usize) -> bool {
    n != 0 && (n & (n - 1) == 0)
}
