use super::helper::get_tree_element;
use super::parameters::LmsParameter;
use crate::{
    constants::LmsTreeIdentifier,
    hasher::HashChain,
    hss::aux::MutableExpandedAuxData,
    lm_ots::parameters::LmotsParameter,
    lms::definitions::{LmsPrivateKey, LmsPublicKey},
    Seed,
};

pub fn generate_private_key<H: HashChain>(
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

pub fn generate_public_key<H: HashChain>(
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
