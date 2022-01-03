use crate::{
    hasher::HashChain, lm_ots::parameters::LmotsParameter, lms::parameters::LmsParameter,
    LmotsAlgorithm, LmsAlgorithm,
};

/**
 * Specify `Winternitz Parameter` ([`LmotsAlgorithm`]) and `Tree Height` ([`LmsAlgorithm`]) for one HSS Level.
 * An array is passed to the [`crate::keygen`] function describing each HSS Level respectively.
 * */
#[derive(Clone, PartialEq)]
pub struct HssParameter<H: HashChain> {
    lmots_parameter: LmotsParameter<H>,
    lms_parameter: LmsParameter<H>,
}

impl<H: HashChain> Copy for HssParameter<H> {}

impl<H: HashChain> HssParameter<H> {
    pub fn new(lmots_parameter: LmotsAlgorithm, lms_parameter: LmsAlgorithm) -> Self {
        let lmots_parameter = lmots_parameter
            .construct_parameter()
            .expect("Use available Lmots parameter.");
        let lms_parameter = lms_parameter
            .construct_parameter()
            .expect("Use available LMS parameter.");
        HssParameter {
            lmots_parameter,
            lms_parameter,
        }
    }

    pub fn get_lmots_parameter(&self) -> &LmotsParameter<H> {
        &self.lmots_parameter
    }

    pub fn get_lms_parameter(&self) -> &LmsParameter<H> {
        &self.lms_parameter
    }
}

impl<H: HashChain> HssParameter<H> {
    pub fn construct_default_parameters() -> Self {
        let lmots_parameter = LmotsAlgorithm::LmotsW1;
        let lms_parameter = LmsAlgorithm::LmsH5;

        HssParameter::new(lmots_parameter, lms_parameter)
    }
}

impl<H: HashChain> Default for HssParameter<H> {
    fn default() -> Self {
        let lmots_parameter = LmotsAlgorithm::LmotsW1;
        let lms_parameter = LmsAlgorithm::LmsH5;

        HssParameter::new(lmots_parameter, lms_parameter)
    }
}
