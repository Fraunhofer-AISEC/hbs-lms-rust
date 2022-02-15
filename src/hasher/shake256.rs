use tinyvec::ArrayVec;

use sha3::{
    digest::{
        typenum::U32, ExtendableOutput, ExtendableOutputReset, FixedOutput, FixedOutputReset,
        Output, OutputSizeUser, Reset, Update, XofReader,
    },
    Shake256 as Hasher,
};

use crate::constants::MAX_HASH_SIZE;

use super::HashChain;

/**
 * Extension of [`sha3::Shake256`], which can be passed into the library, as it implements the [`HashChain`] trait.
 * */
#[derive(Debug, Default, Clone)]
pub struct Shake256 {
    hasher: Hasher,
}

impl HashChain for Shake256 {
    const OUTPUT_SIZE: u16 = 32;
    const BLOCK_SIZE: u16 = 64;

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

impl OutputSizeUser for Shake256 {
    type OutputSize = U32;
}

impl FixedOutput for Shake256 {
    fn finalize_into(self, out: &mut Output<Self>) {
        self.hasher.finalize_xof().read(out);
    }
}

impl Reset for Shake256 {
    fn reset(&mut self) {
        *self = Default::default();
    }
}

impl FixedOutputReset for Shake256 {
    fn finalize_into_reset(&mut self, out: &mut Output<Self>) {
        self.hasher.finalize_xof_reset().read(out);
    }
}

impl Update for Shake256 {
    fn update(&mut self, data: &[u8]) {
        self.hasher.update(data);
    }
}

impl PartialEq for Shake256 {
    fn eq(&self, _: &Self) -> bool {
        false
    }
}
