use crate::{constants, hasher::HashChain, hss::parameter::HssParameter};

use tinyvec::ArrayVec;
use zeroize::{Zeroize, ZeroizeOnDrop};

#[derive(Clone, PartialEq, Eq)]
pub struct SstsParameter<H: HashChain> {
    hss_parameters: ArrayVec<[HssParameter<H>; constants::REF_IMPL_MAX_ALLOWED_HSS_LEVELS]>,
    // TODO use SstExtension here?
    top_div_height: u8,
    signing_entity_idx: u8, // starting with 1
}

impl<H: HashChain> Copy for SstsParameter<H> {}

impl<H: HashChain> SstsParameter<H> {
    pub fn new(
        hss_params: ArrayVec<[HssParameter<H>; constants::REF_IMPL_MAX_ALLOWED_HSS_LEVELS]>,
        top_div_height: u8,
        signing_entity_idx: u8,
    ) -> Self {
        SstsParameter {
            hss_parameters: hss_params,
            top_div_height, // e.g. LMS height of 5 and top_div_height 3: division top/bottom is 3/2 which would result in 2^3 = 8 signing entities
            signing_entity_idx,
        }
    }

    pub fn get_hss_parameters(
        &self,
    ) -> &ArrayVec<[HssParameter<H>; constants::REF_IMPL_MAX_ALLOWED_HSS_LEVELS]> {
        &self.hss_parameters
    }

    pub fn get_top_div_height(&self) -> u8 {
        self.top_div_height
    }

    pub fn get_signing_entity_idx(&self) -> u8 {
        self.signing_entity_idx
    }
}

#[derive(Debug, Default, Clone, PartialEq, Eq, Zeroize, ZeroizeOnDrop)]
pub struct SstExtension {
    pub signing_entity_idx: u8,
    pub top_div_height: u8,
}

impl SstExtension {
    pub fn from_slice(data: &[u8]) -> Result<Self, ()> {
        if data.len() != constants::REF_IMPL_SSTS_EXT_SIZE {
            return Err(());
        }

        Ok(SstExtension {
            signing_entity_idx: data[0],
            top_div_height: data[1],
        })
    }
}
