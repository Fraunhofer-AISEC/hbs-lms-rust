use super::helper::get_tree_element;
use super::parameters::LmsParameter;
use crate::constants::*;
use crate::hasher::Hasher;
use crate::lm_ots::parameters::LmotsParameter;
use crate::lms::definitions::LmsPrivateKey;
use crate::lms::definitions::LmsPublicKey;

pub fn generate_private_key_with_seed<H: Hasher>(seed: Seed, i: IType, lmots_parameter: LmotsParameter<H>, lms_parameter: LmsParameter<H>) -> LmsPrivateKey<H> {
    LmsPrivateKey::new(seed, i, lmots_parameter, lms_parameter)
}

pub fn generate_private_key<H: Hasher>(
    lmots_parameter: LmotsParameter<H>,
    lms_parameter: LmsParameter<H>,
) -> LmsPrivateKey<H> {
    let mut i: IType = [0u8; 16];
    crate::util::random::get_random(&mut i);

    let mut seed: Seed = [0u8; 32];
    crate::util::random::get_random(&mut seed);

    LmsPrivateKey::new(seed, i, lmots_parameter, lms_parameter)
}

pub fn generate_public_key<H: Hasher>(private_key: &LmsPrivateKey<H>) -> LmsPublicKey<H> {
    let public_key = get_tree_element(1, private_key);

    LmsPublicKey::new(
        public_key,
        private_key.I,
        private_key.lmots_parameter,
        private_key.lms_parameter,
    )
}
