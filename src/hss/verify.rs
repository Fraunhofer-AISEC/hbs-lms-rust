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

    if signature.level + 1 != public_key.level {
        return Err("Signature level and public key level does not match");
    }

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

#[cfg(test)]
mod tests {
    use crate::hss::definitions::HssPrivateKey;
    use crate::hss::signing::HssSignature;
    use crate::hss::verify::verify;

    use crate::lms::parameter::*;
    use crate::lm_ots::parameter::*;

    type OTS = LmotsSha256N32W2;
    type LMS = LmsSha256M32H5;
    const LEVEL: usize = 3;

    #[test]
    fn test_hss_verify() {
        let mut private_key: HssPrivateKey<OTS, LMS, LEVEL> = HssPrivateKey::generate().expect("Should generate HSS private key");
        let public_key = private_key.get_public_key();

        let mut message = [42, 57, 20, 59, 33, 1, 49, 3, 99, 130, 50, 20];

        let signature = HssSignature::sign(&mut private_key, &message).expect("Should sign message");

        assert!(verify(&signature, &public_key, &message).is_ok());

        message[0] = !message[0];

        assert!(verify(&signature, &public_key, &message).is_err());
    }
}