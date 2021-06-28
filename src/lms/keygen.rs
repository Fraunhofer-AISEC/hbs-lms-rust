use super::definitions::LmsAlgorithmParameter;
use super::helper::get_tree_element;
use crate::lm_ots::definitions::IType;
use crate::lm_ots::definitions::Seed;
use crate::lm_ots::parameter::LmotsParameter;
use crate::lms::definitions::LmsPrivateKey;
use crate::lms::definitions::LmsPublicKey;

pub fn generate_private_key<P: LmotsParameter>(
    lms_parameter: LmsAlgorithmParameter,
) -> LmsPrivateKey<P> {
    let mut i: IType = [0u8; 16];
    crate::util::random::get_random(&mut i);

    let mut seed: Seed = [0u8; 32];
    crate::util::random::get_random(&mut seed);

    LmsPrivateKey::new(lms_parameter, seed, i)
}

pub fn generate_public_key<P: LmotsParameter>(private_key: &LmsPrivateKey<P>) -> LmsPublicKey<P> {
    let public_key = get_tree_element(1, private_key);

    LmsPublicKey::new(public_key, private_key.lms_parameter, private_key.I)
}
