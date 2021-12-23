use core::convert::TryFrom;
use tinyvec::ArrayVec;

use sha2::{Digest, Sha256};

use crate::constants::MAX_HASH_SIZE;

use super::Hasher;

/**
 * Standard software implementation for Sha256. Can be passed into the library, because it implements the `Hasher` trait.
 * */
#[derive(Debug, Default, Clone)]
pub struct Sha256Hasher {
    hasher: Sha256,
}

impl Hasher for Sha256Hasher {
    const OUTPUT_SIZE: u16 = 32;
    const BLOCK_SIZE: u16 = 64;

    fn new() -> Self {
        Sha256Hasher {
            hasher: Sha256::default(),
        }
    }

    fn update(&mut self, data: &[u8]) {
        self.hasher.update(data);
    }

    fn chain(self, data: &[u8]) -> Self {
        Sha256Hasher {
            hasher: self.hasher.chain_update(data),
        }
    }

    fn finalize(self) -> ArrayVec<[u8; MAX_HASH_SIZE]> {
        let result = ArrayVec::try_from(self.hasher.finalize().iter().as_slice()).unwrap();
        result
    }

    fn finalize_reset(&mut self) -> ArrayVec<[u8; MAX_HASH_SIZE]> {
        let result = ArrayVec::try_from(self.hasher.finalize_reset().iter().as_slice()).unwrap();
        result
    }
}

impl PartialEq for Sha256Hasher {
    fn eq(&self, _: &Self) -> bool {
        true
    }
}
