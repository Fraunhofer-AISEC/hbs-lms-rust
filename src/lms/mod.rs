use crate::hasher::Hasher;
use crate::hss::parameter::HssParameter;
use crate::lm_ots::parameters::LmotsParameter;
use crate::lms::definitions::LmsPrivateKey;
use crate::lms::definitions::LmsPublicKey;

use self::parameters::LmsParameter;

pub mod definitions;
mod helper;
mod keygen;
pub mod parameters;
pub mod signing;
pub mod verify;

pub struct LmsKeyPair<H: Hasher> {
    pub private_key: LmsPrivateKey<H>,
    pub public_key: LmsPublicKey<H>,
}

pub fn generate_key_pair<H: Hasher>(parameter: &HssParameter<H>) -> LmsKeyPair<H> {
    let lmots_parameter = parameter.get_lmots_parameter();
    let lms_parameter = parameter.get_lms_parameter();

    let private_key = generate_private_key(*lmots_parameter, *lms_parameter);
    let public_key = generate_public_key(&private_key);
    LmsKeyPair {
        private_key,
        public_key,
    }
}

pub fn generate_private_key<H: Hasher>(
    lmots_parameter: LmotsParameter<H>,
    lms_parameter: LmsParameter<H>,
) -> LmsPrivateKey<H> {
    keygen::generate_private_key(lmots_parameter, lms_parameter)
}

pub fn generate_public_key<H: Hasher>(private_key: &LmsPrivateKey<H>) -> LmsPublicKey<H> {
    keygen::generate_public_key(private_key)
}
