use crate::{constants, hasher::HashChain, hss::parameter::HssParameter};

use tinyvec::ArrayVec;
use zeroize::{Zeroize, ZeroizeOnDrop};

#[derive(Clone, PartialEq, Eq)]
pub struct SstsParameter<H: HashChain> {
    hss_parameters: ArrayVec<[HssParameter<H>; constants::REF_IMPL_MAX_ALLOWED_HSS_LEVELS]>,
    // TODO/Rework: use SstExtension?
    l0_top_div: u8,
    signing_entity_idx: u8,
}

impl<H: HashChain> Copy for SstsParameter<H> {}

impl<H: HashChain> SstsParameter<H> {
    pub fn new(
        hss_params: ArrayVec<[HssParameter<H>; constants::REF_IMPL_MAX_ALLOWED_HSS_LEVELS]>,
        l0_top_div: u8,
        signing_entity_idx: u8,
    ) -> Self {
        SstsParameter {
            hss_parameters: hss_params,
            l0_top_div,
            signing_entity_idx,
        }
    }

    pub fn get_hss_parameters(
        &self,
    ) -> &ArrayVec<[HssParameter<H>; constants::REF_IMPL_MAX_ALLOWED_HSS_LEVELS]> {
        &self.hss_parameters
    }

    pub fn get_l0_top_div(&self) -> u8 {
        self.l0_top_div
    }

    pub fn get_signing_entity_idx(&self) -> u8 {
        self.signing_entity_idx
    }
}

#[derive(Debug, Default, Clone, PartialEq, Eq, Zeroize, ZeroizeOnDrop)]
pub struct SstExtension {
    pub signing_entity_idx: u8, // from 1 to (2^l0_top_div)
    pub l0_top_div: u8, // e.g. L-0 LMS height of 5 and l0_top_div = 3: division top/bottom is 3/2 -> 2^3 = 8 signing entities
}

impl SstExtension {
    // TODO/Review: unlike in all other locations, clippy reports
    //   "this returns a `Result<_, ()>`" and "use a custom `Error` type instead"
    //   see "Result<Self, ()>" in "hss/reference_impl_private_key.rs" -> CompressedParameterSet
    pub fn from_slice(data: &[u8]) -> Result<Self, ()> {
        if data.len() != constants::REF_IMPL_SSTS_EXT_SIZE {
            return Err(());
        }

        Ok(SstExtension {
            signing_entity_idx: data[0],
            l0_top_div: data[1],
        })
    }
}
