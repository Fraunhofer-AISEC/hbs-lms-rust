use crate::{
    hasher::Hasher, lm_ots::parameters::LmotsParameter, lms::parameters::LmsParameter,
    LmotsAlgorithm, LmsAlgorithm,
};

/**
 * Specify Winternitz parameter and Tree height for one HSS Level.
 * An array is passed to the `keygen` function describing each HSS level respectively.
 * */
#[derive(Clone, PartialEq)]
pub struct HssParameter<H: Hasher> {
    lmots_parameter: LmotsParameter<H>,
    lms_parameter: LmsParameter<H>,
}

impl<H: Hasher> Copy for HssParameter<H> {}

impl<H: Hasher> HssParameter<H> {
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

impl<H: Hasher> HssParameter<H> {
    pub fn construct_default_parameters() -> Self {
        let lmots_parameter = LmotsAlgorithm::LmotsW1;
        let lms_parameter = LmsAlgorithm::LmsH5;

        HssParameter::new(lmots_parameter, lms_parameter)
    }
}

impl<H: Hasher> Default for HssParameter<H> {
    fn default() -> Self {
        let lmots_parameter = LmotsAlgorithm::LmotsW1;
        let lms_parameter = LmsAlgorithm::LmsH5;

        HssParameter::new(lmots_parameter, lms_parameter)
    }
}
