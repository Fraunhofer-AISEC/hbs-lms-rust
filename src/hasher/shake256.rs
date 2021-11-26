use arrayvec::ArrayVec;
use core::convert::TryFrom;

use sha3::{
    digest::{ExtendableOutput, Update, XofReader},
    Shake256,
};

use crate::constants::MAX_HASH_SIZE;

use super::Hasher;

/**
 * Standard software implementation for Shake256. Can be passed into the library, because it implements the `Hasher` trait.
 * */
#[derive(Default, Clone)]
pub struct Shake256Hasher {
    hasher: Shake256,
}

impl Shake256Hasher {
    pub fn new() -> Self {
        Shake256Hasher {
            hasher: Shake256::default(),
        }
    }
}

impl Hasher for Shake256Hasher {
    const OUTPUT_SIZE: u16 = 32;
    const BLOCK_SIZE: u16 = 64;

    fn get_hasher() -> Self {
        Self::new()
    }

    fn update(&mut self, data: &[u8]) {
        self.hasher.update(data);
    }

    fn finalize(self) -> ArrayVec<u8, MAX_HASH_SIZE> {
        let mut digest = [0u8; 32];
        self.hasher.finalize_xof().read(&mut digest);
        ArrayVec::try_from(digest).unwrap()
    }

    fn finalize_reset(&mut self) -> ArrayVec<u8, MAX_HASH_SIZE> {
        let mut digest = [0u8; 32];
        self.hasher.finalize_xof_reset().read(&mut digest);
        ArrayVec::try_from(digest).unwrap()
    }
}

impl PartialEq for Shake256Hasher {
    fn eq(&self, _: &Self) -> bool {
        true
    }
}
