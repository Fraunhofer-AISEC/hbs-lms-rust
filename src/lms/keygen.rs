use super::helper::get_tree_element;
use super::parameter::LmsParameter;
use crate::constants::*;
use crate::lm_ots::parameter::LmotsParameter;
use crate::lms::definitions::LmsPrivateKey;
use crate::lms::definitions::LmsPublicKey;

pub fn generate_private_key<OTS: LmotsParameter, LMS: LmsParameter>() -> LmsPrivateKey<OTS, LMS> {
    let mut i: IType = [0u8; 16];
    crate::util::random::get_random(&mut i);

    let mut seed: Seed = [0u8; 32];
    crate::util::random::get_random(&mut seed);

    LmsPrivateKey::new(seed, i)
}

pub fn generate_public_key<OTS: LmotsParameter, LMS: LmsParameter>(
    private_key: &LmsPrivateKey<OTS, LMS>,
) -> LmsPublicKey<OTS, LMS> {
    let public_key = get_tree_element(1, private_key);

    LmsPublicKey::new(public_key, private_key.I)
}
