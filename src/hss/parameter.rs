use crate::{
    hasher::Hasher, LmotsAlgorithm, LmotsParameter, LmsAlgorithm, LmsParameter, Sha256Hasher,
};

#[derive(Clone, Copy)]
pub struct HssParameter<H: Hasher> {
    lmots_parameter: LmotsParameter<H>,
    lms_parameter: LmsParameter<H>,
}

impl<H: Hasher> HssParameter<H> {
    pub fn new(lmots_parameter: LmotsParameter<H>, lms_parameter: LmsParameter<H>) -> Self {
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

impl HssParameter<Sha256Hasher> {
    pub fn construct_default_parameters() -> Self {
        let lmots_parameter = LmotsAlgorithm::construct_default_parameter();
        let lms_parameter = LmsAlgorithm::construct_default_parameter();

        HssParameter::new(lmots_parameter, lms_parameter)
    }
}

impl<H: Hasher> Default for HssParameter<H> {
    fn default() -> Self {
        let lmots_parameter = LmotsParameter::default();
        let lms_parameter = LmsParameter::default();

        HssParameter::new(lmots_parameter, lms_parameter)
    }
}
