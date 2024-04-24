use crate::hasher::HashChain;
use crate::hss::aux::MutableExpandedAuxData;
use crate::hss::parameter::HssParameter;
use crate::hss::reference_impl_private_key::SeedAndLmsTreeIdentifier;
use crate::lms::definitions::LmsPrivateKey;
use crate::lms::definitions::LmsPublicKey;
use crate::sst::parameters::SstExtension;

pub mod definitions;
pub(crate) mod helper;
pub mod parameters;
pub mod signing;
pub mod verify;

pub struct LmsKeyPair<H: HashChain> {
    pub private_key: LmsPrivateKey<H>,
    pub public_key: LmsPublicKey<H>,
}

pub fn generate_key_pair<H: HashChain>(
    seed: &SeedAndLmsTreeIdentifier<H>,
    hss_param: &HssParameter<H>,
    used_leafs_index: &u32,
    aux_data: &mut Option<MutableExpandedAuxData>,
    sst_ext: Option<SstExtension>,
) -> LmsKeyPair<H> {
    let lmots_parameter = hss_param.get_lmots_parameter();
    let lms_parameter = hss_param.get_lms_parameter();

    let private_key = LmsPrivateKey::new(
        seed.seed.clone(),
        seed.lms_tree_identifier,
        *used_leafs_index,
        *lmots_parameter,
        *lms_parameter,
        sst_ext,
    );
    let public_key = LmsPublicKey::new(&private_key, aux_data);

    LmsKeyPair {
        private_key,
        public_key,
    }
}
