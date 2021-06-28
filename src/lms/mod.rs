use crate::lm_ots::parameter::LmotsParameter;
use crate::lms::definitions::LmsPrivateKey;
use crate::lms::definitions::LmsPublicKey;

use self::definitions::LmsAlgorithmParameter;
use self::signing::LmsSignature;

pub mod definitions;
mod helper;
mod keygen;
pub mod parameter;
pub mod signing;
mod verify;

pub fn generate_private_key<OTS: LmotsParameter>(
    lms_parameter: LmsAlgorithmParameter,
) -> LmsPrivateKey<OTS> {
    keygen::generate_private_key(lms_parameter)
}

pub fn generate_public_key<OTS: LmotsParameter>(
    private_key: &LmsPrivateKey<OTS>,
) -> LmsPublicKey<OTS> {
    keygen::generate_public_key(private_key)
}

pub fn verify<OTS: LmotsParameter>(message: &[u8], signature: &[u8], public_key: &[u8]) -> bool {
    let public_key = match LmsPublicKey::<OTS>::from_binary_representation(public_key) {
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
