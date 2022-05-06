use core::convert::TryFrom;
use tinyvec::TinyVec;

use sha2::{
    digest::{typenum::U32, FixedOutput, FixedOutputReset, Output, OutputSizeUser, Reset, Update},
    Sha256 as Hasher,
};

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

    fn finalize(self) -> TinyVec<[u8; MAX_HASH_SIZE]> {
        TinyVec::try_from(self.hasher.finalize_fixed().as_slice()).unwrap()
    }

    fn finalize_reset(&mut self) -> TinyVec<[u8; MAX_HASH_SIZE]> {
        TinyVec::try_from(self.hasher.finalize_fixed_reset().as_slice()).unwrap()
    }
}

impl OutputSizeUser for Sha256 {
    type OutputSize = U32;
}

impl FixedOutput for Sha256 {
    fn finalize_into(self, out: &mut Output<Self>) {
        *out = self.hasher.finalize_fixed();
    }
}

impl Reset for Sha256 {
    fn reset(&mut self) {
        *self = Default::default();
    }
}

impl FixedOutputReset for Sha256 {
    fn finalize_into_reset(&mut self, out: &mut Output<Self>) {
        *out = self.hasher.finalize_fixed_reset();
    }
}

impl Update for Sha256 {
    fn update(&mut self, data: &[u8]) {
        self.hasher.update(data);
    }
}

impl PartialEq for Sha256 {
    fn eq(&self, _: &Self) -> bool {
        false
    }
}
