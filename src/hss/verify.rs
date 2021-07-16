use crate::{
    hasher::Hasher,
    lms::{self},
};

use super::{definitions::HssPublicKey, signing::HssSignature};

pub fn verify<H: Hasher>(
    signature: &HssSignature<H>,
    public_key: &HssPublicKey<H>,
    message: &[u8],
) -> Result<(), &'static str> {
    if signature.level + 1 != public_key.level {
        return Err("Signature level and public key level does not match");
    }

    let mut key = &public_key.public_key;
    for i in 0..public_key.level - 1 {
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
    use crate::hasher::sha256::Sha256Hasher;
    use crate::hasher::Hasher;
    use crate::hss::definitions::HssPrivateKey;
    use crate::hss::definitions::HssPublicKey;
    use crate::hss::rfc_private_key::RfcPrivateKey;
    use crate::hss::signing::HssSignature;
    use crate::hss::verify::verify;
    use crate::HssParameter;

    #[test]
    fn test_hss_verify() {
        let private_key = RfcPrivateKey::<Sha256Hasher>::generate(&[
            HssParameter::construct_default_parameters(),
            HssParameter::construct_default_parameters(),
        ])
        .unwrap();

        let mut private_key = HssPrivateKey::from(&private_key).unwrap();

        let public_key = private_key.get_public_key();

        let mut message = [42, 57, 20, 59, 33, 1, 49, 3, 99, 130, 50, 20];

        generate_signature_and_verify(&mut private_key, &public_key, &mut message);
        generate_signature_and_verify(&mut private_key, &public_key, &mut message);
    }

    fn generate_signature_and_verify<H: Hasher>(
        private_key: &mut HssPrivateKey<H>,
        public_key: &HssPublicKey<H>,
        message: &mut [u8],
    ) {
        let signature = HssSignature::sign(private_key, &message).expect("Should sign message");

        assert!(verify(&signature, &public_key, &message).is_ok());

        message[0] = !message[0];

        assert!(verify(&signature, &public_key, &message).is_err());
    }
}
