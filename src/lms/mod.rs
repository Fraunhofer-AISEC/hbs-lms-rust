use crate::lms::definitions::LmsPublicKey;
use crate::lms::definitions::LmsPrivateKey;
use crate::lms::definitions::LmsAlgorithmType;
use crate::lm_ots::definitions::LmotsAlgorithmType;

pub mod definitions;
mod keygen;
pub mod signing;
mod verify;

pub fn generate_private_key(lms_type: LmsAlgorithmType, lmots_type: LmotsAlgorithmType) -> LmsPrivateKey {
    keygen::generate_private_key(lms_type, lmots_type)
}

pub fn generate_public_key(private_key: &LmsPrivateKey) -> LmsPublicKey {
    keygen::generate_public_key(private_key)
}