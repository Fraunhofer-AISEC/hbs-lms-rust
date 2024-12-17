use core::convert::TryFrom;
use tinyvec::ArrayVec;

use sha2::{
    digest::{typenum::U32, FixedOutput, FixedOutputReset, Output, OutputSizeUser, Reset, Update},
    Sha256 as Hasher,
};

use crate::constants::MAX_HASH_SIZE;
use crate::hasher::FINALIZED_CTR;

use super::HashChain;

macro_rules! define_sha {
    ($name:ident, $output_size:expr) => {
        /**
         * Extension of [`sha2::Sha256`], which can be passed into the library, as it implements the [`HashChain`] trait.
         * */
        #[derive(Debug, Default, Clone)]
        pub struct $name {
            hasher: Hasher,
        }

        impl HashChain for $name {
            const OUTPUT_SIZE: u16 = $output_size;
            const BLOCK_SIZE: u16 = 64;

            fn finalize(self) -> ArrayVec<[u8; MAX_HASH_SIZE]> {
                unsafe {
                    FINALIZED_CTR = Some(FINALIZED_CTR.map_or(1, |c| c + 1));
                }
                ArrayVec::try_from(&self.hasher.finalize_fixed()[..(Self::OUTPUT_SIZE as usize)])
                    .unwrap()
            }

            fn finalize_reset(&mut self) -> ArrayVec<[u8; MAX_HASH_SIZE]> {
                unsafe {
                    FINALIZED_CTR = Some(FINALIZED_CTR.map_or(1, |c| c + 1));
                }
                ArrayVec::try_from(
                    &self.hasher.finalize_fixed_reset()[..(Self::OUTPUT_SIZE as usize)],
                )
                .unwrap()
            }
        }

        impl OutputSizeUser for $name {
            type OutputSize = U32;
        }

        impl FixedOutput for $name {
            fn finalize_into(self, out: &mut Output<Self>) {
                *out = self.hasher.finalize_fixed();
            }
        }

        impl Reset for $name {
            fn reset(&mut self) {
                *self = Default::default();
            }
        }

        impl FixedOutputReset for $name {
            fn finalize_into_reset(&mut self, out: &mut Output<Self>) {
                *out = self.hasher.finalize_fixed_reset();
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

define_sha!(Sha256_256, 32);

define_sha!(Sha256_192, 24);

define_sha!(Sha256_128, 16);
