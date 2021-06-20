use crate::lm_ots::definitions::LmotsAlgorithmType;
use crate::lms::definitions::LmsAlgorithmType;
use crate::lms::definitions::LmsPrivateKey;
use crate::lms::definitions::LmsPublicKey;

use self::signing::LmsSignature;

pub mod definitions;
mod helper;
mod keygen;
pub mod signing;
mod verify;

pub fn generate_private_key(
    lms_type: LmsAlgorithmType,
    lmots_type: LmotsAlgorithmType,
) -> LmsPrivateKey {
    keygen::generate_private_key(lms_type, lmots_type)
}

pub fn generate_public_key(private_key: &LmsPrivateKey) -> LmsPublicKey {
    keygen::generate_public_key(private_key)
}

pub fn verify(message: &[u8], signature: &[u8], public_key: &[u8]) -> bool {
    let public_key = match LmsPublicKey::from_binary_representation(public_key) {
        None => return false,
        Some(x) => x,
    };

    let signature = match LmsSignature::from_binary_representation(signature) {
        None => return false,
        Some(x) => x,
    };

    let result = crate::lms::verify::verify(&signature, &public_key, message);

    result.is_ok()
}
