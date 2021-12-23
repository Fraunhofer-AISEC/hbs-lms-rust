use tinyvec::ArrayVec;

use sha3::{
    digest::{ExtendableOutput, ExtendableOutputReset, Update, XofReader},
    Shake256,
};

use crate::constants::MAX_HASH_SIZE;

use super::Hasher;

/**
 * Standard software implementation for Shake256. Can be passed into the library, because it implements the `Hasher` trait.
 * */
#[derive(Debug, Default, Clone)]
pub struct Shake256Hasher {
    hasher: Shake256,
}

impl Hasher for Shake256Hasher {
    const OUTPUT_SIZE: u16 = 32;
    const BLOCK_SIZE: u16 = 64;

    fn new() -> Self {
        Shake256Hasher {
            hasher: Shake256::default(),
        }
    }

    fn update(&mut self, data: &[u8]) {
        self.hasher.update(data);
    }

    fn chain(self, data: &[u8]) -> Self {
        Shake256Hasher {
            hasher: self.hasher.chain(data),
        }
    }

    fn finalize(self) -> ArrayVec<[u8; MAX_HASH_SIZE]> {
        let mut digest = [0u8; Self::OUTPUT_SIZE as usize];
        self.hasher.finalize_xof().read(&mut digest);
        ArrayVec::from(digest)
    }

    fn finalize_reset(&mut self) -> ArrayVec<[u8; MAX_HASH_SIZE]> {
        let mut digest = [0u8; Self::OUTPUT_SIZE as usize];
        self.hasher.finalize_xof_reset().read(&mut digest);
        ArrayVec::from(digest)
    }
}

impl PartialEq for Shake256Hasher {
    fn eq(&self, _: &Self) -> bool {
        #[cfg(test)]
        return true;
        #[cfg(not(test))]
        return false;
    }
}
