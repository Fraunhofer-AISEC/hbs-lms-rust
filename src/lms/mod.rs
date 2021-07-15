use crate::hasher::Hasher;
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

pub fn generate_key_pair<H: Hasher>(
    lmots_parameter: LmotsParameter<H>,
    lms_parameter: LmsParameter<H>,
) -> LmsKeyPair<H> {
    let private_key = keygen::generate_private_key(lmots_parameter, lms_parameter);
    let public_key = keygen::generate_public_key(&private_key);
    LmsKeyPair {
        private_key,
        public_key,
    }
}
