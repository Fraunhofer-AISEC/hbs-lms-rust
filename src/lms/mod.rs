use crate::lm_ots::parameter::LmotsParameter;
use crate::lms::definitions::LmsPrivateKey;
use crate::lms::definitions::LmsPublicKey;

use self::parameter::LmsParameter;
use self::signing::LmsSignature;

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

pub fn verify<OTS: LmotsParameter, LMS: LmsParameter>(
    message: &[u8],
    signature: &[u8],
    public_key: &[u8],
) -> bool {
    let public_key = match LmsPublicKey::<OTS, LMS>::from_binary_representation(public_key) {
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
