use crate::{
    hasher::HashChain,
    hss::parameter::HssParameter,
};

use tinyvec::ArrayVec;


#[derive(Clone, PartialEq, Eq)]
pub struct SstsParameter<H: HashChain> {
    hss_parameters: ArrayVec<[HssParameter<H>; 5]>, // @TODO replace 5 with some defined constant; currently min=max=1
    top_height: u8,
}


impl<H: HashChain> Copy for SstsParameter<H> {}

impl<H: HashChain> SstsParameter<H> {
    pub fn new(hss_params: ArrayVec<[HssParameter<H>; 5]>, top_height: u8) -> Self {

        SstsParameter {
            hss_parameters: hss_params,
            top_height, // e.g. LMS height of 5 and top_height 3, we divide 3/3 (we consider one node as part of both tree parts)
                        // would give us 2^3 = 8 signing entities
        }
    }

    pub fn get_hss_parameters(&self) -> &ArrayVec<[HssParameter<H>; 5]> {
        &self.hss_parameters
    }

    pub fn get_top_height(&self) -> u8 {
        self.top_height
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
