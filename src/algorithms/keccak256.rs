use rs_merkle::Hasher;
use sha3::{Digest, Keccak256};

#[derive(Clone)]
pub struct Keccak256Algorithm {}

impl Hasher for Keccak256Algorithm {
    type Hash = [u8; 32];

    fn hash(data: &[u8]) -> [u8; 32] {
        let mut hasher = Keccak256::new();

        hasher.update(data);
        <[u8; 32]>::from(hasher.finalize())
    }
}