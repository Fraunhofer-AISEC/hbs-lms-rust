use crate::constants::IType;
use crate::constants::Seed;
use crate::hasher::Hasher;
use crate::hss::parameter::HssParameter;
use crate::hss::rfc_private_key::SeedAndI;
use crate::lm_ots::parameters::LmotsParameter;
use crate::lms::definitions::LmsPrivateKey;
use crate::lms::definitions::LmsPublicKey;

use self::parameters::LmsParameter;

pub mod definitions;
mod helper;
pub mod keygen;
pub mod parameters;
pub mod signing;
pub mod verify;

pub struct LmsKeyPair<H: Hasher> {
    pub private_key: LmsPrivateKey<H>,
    pub public_key: LmsPublicKey<H>,
}

pub fn generate_key_pair_with_seed<H: Hasher>(
    seed: &SeedAndI,
    parameter: &HssParameter<H>,
) -> LmsKeyPair<H> {
    let lmots_parameter = parameter.get_lmots_parameter();
    let lms_parameter = parameter.get_lms_parameter();

    let private_key =
        keygen::generate_private_key_with_seed(seed.seed, seed.i, *lmots_parameter, *lms_parameter);
    let public_key = keygen::generate_public_key(&private_key);

    LmsKeyPair {
        private_key,
        public_key,
    }
}

pub fn generate_key_pair<H: Hasher>(parameter: &HssParameter<H>) -> LmsKeyPair<H> {
    let lmots_parameter = parameter.get_lmots_parameter();
    let lms_parameter = parameter.get_lms_parameter();

    let private_key = keygen::generate_private_key(*lmots_parameter, *lms_parameter);
    let public_key = keygen::generate_public_key(&private_key);
    LmsKeyPair {
        private_key,
        public_key,
    }
}
