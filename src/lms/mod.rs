use crate::lm_ots::parameter::LmotsParameter;
use crate::lms::definitions::LmsPrivateKey;
use crate::lms::definitions::LmsPublicKey;

use self::parameter::LmsParameter;

pub mod definitions;
mod helper;
mod keygen;
pub mod parameter;
pub mod signing;
pub mod verify;

pub struct LmsKeyPair<OTS: LmotsParameter, LMS: LmsParameter> {
    pub private_key: LmsPrivateKey<OTS, LMS>,
    pub public_key: LmsPublicKey<OTS, LMS>,
}

pub fn generate_key_pair<OTS: LmotsParameter, LMS: LmsParameter>() -> LmsKeyPair<OTS, LMS> {
    let private_key = generate_private_key();
    let public_key = generate_public_key(&private_key);
    LmsKeyPair {
        private_key,
        public_key,
    }
}

pub fn generate_private_key<OTS: LmotsParameter, LMS: LmsParameter>() -> LmsPrivateKey<OTS, LMS> {
    keygen::generate_private_key()
}

pub fn generate_public_key<OTS: LmotsParameter, LMS: LmsParameter>(
    private_key: &LmsPrivateKey<OTS, LMS>,
) -> LmsPublicKey<OTS, LMS> {
    keygen::generate_public_key(private_key)
}
