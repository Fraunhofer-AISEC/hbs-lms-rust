use tinyvec::TinyVec;

use sha3::{
    digest::{
        typenum::U32, ExtendableOutput, ExtendableOutputReset, FixedOutput, FixedOutputReset,
        Output, OutputSizeUser, Reset, Update, XofReader,
    },
    Shake256 as Hasher,
};

use crate::constants::MAX_HASH_SIZE;

use super::HashChain;

macro_rules! define_shake {
    ($name:ident, $output_size:expr) => {
        /**
         * Extension of [`sha3::Shake256`], which can be passed into the library, as it implements the [`HashChain`] trait.
         * */
        #[derive(Debug, Default, Clone)]
        pub struct $name {
            hasher: Hasher,
        }

        impl HashChain for $name {
            const OUTPUT_SIZE: u16 = $output_size;
            const BLOCK_SIZE: u16 = 64;

            fn finalize(self) -> TinyVec<[u8; MAX_HASH_SIZE]> {
                let mut digest = [0u8; MAX_HASH_SIZE];
                self.hasher.finalize_xof().read(&mut digest);
                TinyVec::from_array_len(digest, Self::OUTPUT_SIZE as usize)
            }

            fn finalize_reset(&mut self) -> TinyVec<[u8; MAX_HASH_SIZE]> {
                let mut digest = [0u8; MAX_HASH_SIZE];
                self.hasher.finalize_xof_reset().read(&mut digest);
                TinyVec::from_array_len(digest, Self::OUTPUT_SIZE as usize)
            }
        }

        impl OutputSizeUser for $name {
            type OutputSize = U32;
        }

        impl FixedOutput for $name {
            fn finalize_into(self, out: &mut Output<Self>) {
                self.hasher.finalize_xof().read(out);
            }
        }

        impl Reset for $name {
            fn reset(&mut self) {
                *self = Default::default();
            }
        }

        impl FixedOutputReset for $name {
            fn finalize_into_reset(&mut self, out: &mut Output<Self>) {
                self.hasher.finalize_xof_reset().read(out);
            }
        }

        impl Update for $name {
            fn update(&mut self, data: &[u8]) {
                self.hasher.update(data);
            }
        }

        impl PartialEq for $name {
            fn eq(&self, _: &Self) -> bool {
                false
            }
        }
    };
}

define_shake!(Shake256_256, 32);

define_shake!(Shake256_192, 24);

define_shake!(Shake256_128, 16);
