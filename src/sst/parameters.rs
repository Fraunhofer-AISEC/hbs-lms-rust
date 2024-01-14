use crate::{constants, hasher::HashChain, hss::parameter::HssParameter};

use core::convert::TryInto;
use tinyvec::ArrayVec;
use zeroize::{Zeroize, ZeroizeOnDrop};

#[derive(Clone, PartialEq, Eq)]
pub struct SstsParameter<H: HashChain> {
    hss_parameters: ArrayVec<[HssParameter<H>; constants::REF_IMPL_MAX_ALLOWED_HSS_LEVELS]>,
    top_height: u8,
    signing_entity_idx: u8, // starting with 1
}

impl<H: HashChain> Copy for SstsParameter<H> {}

impl<H: HashChain> SstsParameter<H> {
    pub fn new(
        hss_params: ArrayVec<[HssParameter<H>; constants::REF_IMPL_MAX_ALLOWED_HSS_LEVELS]>,
        top_height: u8,
        entity_idx: u8,
    ) -> Self {
        SstsParameter {
            hss_parameters: hss_params,
            top_height, // e.g. LMS height of 5 and top_height 3: division top/bottom is 3/2 which would result in 2^3 = 8 signing entities
            signing_entity_idx: entity_idx,
        }
    }

    pub fn get_hss_parameters(
        &self,
    ) -> &ArrayVec<[HssParameter<H>; constants::REF_IMPL_MAX_ALLOWED_HSS_LEVELS]> {
        &self.hss_parameters
    }

    pub fn get_top_height(&self) -> u8 {
        self.top_height
    }

    pub fn get_entity_idx(&self) -> u8 {
        self.signing_entity_idx
    }
}

/*
impl<H: HashChain> SstsParameter<H> {
    pub fn construct_default_parameters() -> Self {
        let lmots_parameter = LmotsAlgorithm::LmotsW1;
        let lms_parameter = LmsAlgorithm::LmsH5;

        SstsParameter::new(lmots_parameter, lms_parameter, 3)
    }
}

impl<H: HashChain> Default for SstsParameter<H> {
    fn default() -> Self {
        let lmots_parameter = LmotsAlgorithm::LmotsW1;
        let lms_parameter = LmsAlgorithm::LmsH5;

        SstsParameter::new(lmots_parameter, lms_parameter, 3)
    }
}
 */

#[derive(Debug, Default, Clone, PartialEq, Eq, Zeroize, ZeroizeOnDrop)]
pub struct SstExtension {
    pub signing_instance: u8,
    pub top_tree_height: u8,
}

impl SstExtension {
    pub fn from_slice(data: &[u8]) -> Result<Self, ()> {
        if data.len() != constants::REF_IMPL_SSTS_EXT_SIZE {
            return Err(());
        }

        let tmp: u16 = u16::from_be_bytes(data.try_into().unwrap());
        let sst_ext = SstExtension {
            signing_instance: (tmp >> 8) as u8,
            top_tree_height: tmp as u8,
        };

        Ok(sst_ext)
    }
}
