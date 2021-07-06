use crate::{
    lms::{self},
    LmotsParameter, LmsParameter,
};

use super::{definitions::HssPublicKey, signing::HssSignature};

pub fn verify<OTS: LmotsParameter, LMS: LmsParameter, const L: usize>(
    signature: &HssSignature<OTS, LMS, L>,
    public_key: &HssPublicKey<OTS, LMS, L>,
    message: &[u8],
) -> Result<(), &'static str> {
    let mut key = &public_key.public_key;
    for i in 0..L - 1 {
        let sig = &signature.signed_public_keys[i].sig;
        let msg = &signature.signed_public_keys[i].public_key;

        if lms::verify::verify(sig, key, msg.to_binary_representation().as_slice()).is_err() {
            return Err("Could not verify next public key.");
        }
        key = msg;
    }

    lms::verify::verify(&signature.signature, key, message)
}
