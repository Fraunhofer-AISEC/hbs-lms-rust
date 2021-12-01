use super::helper::get_tree_element;
use super::parameters::LmsParameter;
use crate::constants::*;
use crate::hasher::Hasher;
use crate::hss::aux::MutableExpandedAuxData;
use crate::lm_ots::parameters::LmotsParameter;
use crate::lms::definitions::LmsPrivateKey;
use crate::lms::definitions::LmsPublicKey;

pub fn generate_private_key_with_seed<H: Hasher>(
    seed: Seed,
    lms_tree_identifier: LmsTreeIdentifier,
    used_leafs_index: u32,
    lmots_parameter: LmotsParameter<H>,
    lms_parameter: LmsParameter<H>,
) -> LmsPrivateKey<H> {
    LmsPrivateKey::new(
        seed,
        lms_tree_identifier,
        used_leafs_index,
        lmots_parameter,
        lms_parameter,
    )
}

#[cfg(test)]
pub fn generate_private_key<H: Hasher>(
    lmots_parameter: LmotsParameter<H>,
    lms_parameter: LmsParameter<H>,
) -> LmsPrivateKey<H> {
    let mut lms_tree_identifier: LmsTreeIdentifier = [0u8; 16];
    crate::util::random::get_random(&mut lms_tree_identifier);

    let mut seed: Seed = [0u8; 32];
    crate::util::random::get_random(&mut seed);

    LmsPrivateKey::new(seed, lms_tree_identifier, 0, lmots_parameter, lms_parameter)
}

pub fn generate_public_key<H: Hasher>(
    private_key: &LmsPrivateKey<H>,
    aux_data: &mut Option<MutableExpandedAuxData>,
) -> LmsPublicKey<H> {
    let public_key = get_tree_element(1, private_key, aux_data);

    LmsPublicKey::new(
        public_key,
        private_key.lms_tree_identifier,
        private_key.lmots_parameter,
        private_key.lms_parameter,
    )
}
