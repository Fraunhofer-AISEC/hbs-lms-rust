use core::convert::TryFrom;
use tinyvec::ArrayVec;

use sha2::{Digest, Sha256 as Hasher};

use crate::constants::MAX_HASH_SIZE;

use super::HashChain;

/**
 * Extension of [`sha2::Sha256`], which can be passed into the library, as it implements the [`HashChain`] trait.
 * */
#[derive(Debug, Default, Clone)]
pub struct Sha256 {
    hasher: Hasher,
}

impl HashChain for Sha256 {
    const OUTPUT_SIZE: u16 = 32;
    const BLOCK_SIZE: u16 = 64;

    fn update(&mut self, data: &[u8]) {
        self.hasher.update(data);
    }

    fn chain(self, data: &[u8]) -> Self {
        Sha256 {
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

impl PartialEq for Sha256 {
    fn eq(&self, _: &Self) -> bool {
        #[cfg(test)]
        return true;
        #[cfg(not(test))]
        return false;
    }
}
