use crate::lm_ots::parameter::LmotsParameter;
use crate::lms::definitions::LmsPrivateKey;
use crate::lms::definitions::LmsPublicKey;

use self::definitions::LmsAlgorithmParameter;
use self::signing::LmsSignature;

pub mod definitions;
mod helper;
mod keygen;
pub mod signing;
mod verify;

pub fn generate_private_key<P: LmotsParameter>(
    lms_parameter: LmsAlgorithmParameter,
) -> LmsPrivateKey<P> {
    keygen::generate_private_key(lms_parameter)
}

pub fn generate_public_key<P: LmotsParameter>(private_key: &LmsPrivateKey<P>) -> LmsPublicKey<P> {
    keygen::generate_public_key(private_key)
}

pub fn verify<P: LmotsParameter>(message: &[u8], signature: &[u8], public_key: &[u8]) -> bool {
    let public_key = match LmsPublicKey::<P>::from_binary_representation(public_key) {
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
