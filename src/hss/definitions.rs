use crate::{
    lms::definitions::LmsPrivateKey, util::dynamic_array::DynamicArray, LmotsParameter,
    LmsParameter,
};
pub struct HssPrivateKey<OTS: LmotsParameter, LMS: LmsParameter, const L: usize> {
    private_key: DynamicArray<LmsPrivateKey<OTS, LMS>, L>,
}

impl<OTS: LmotsParameter, LMS: LmsParameter, const L: usize> HssPrivateKey<OTS, LMS, L> {
    fn generate() -> Self {}
}

pub struct HssPublicKey<const L: usize> {}

pub struct HssSignature<const L: usize> {}
