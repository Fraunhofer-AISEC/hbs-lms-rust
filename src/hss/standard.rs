use crate::{
    constants::MAX_SIGNATURE_LENGTH, hasher::sha256::Sha256Hasher,
    util::dynamic_array::DynamicArray, LmotsAlgorithmType, LmsAlgorithmType,
};

use super::HssKeyPair;

pub fn hss_verify(message: &[u8], signature: &[u8], public_key: &[u8]) -> bool {
    let none_hasher: Option<Sha256Hasher> = None;
    super::custom::hss_verify(message, signature, public_key, none_hasher)
}

pub fn hss_sign(
    message: &[u8],
    private_key: &mut [u8],
) -> Option<DynamicArray<u8, MAX_SIGNATURE_LENGTH>> {
    let none_hasher: Option<Sha256Hasher> = None;
    super::custom::hss_sign(message, private_key, none_hasher)
}

pub fn hss_keygen(lms_type: LmsAlgorithmType, lmots_type: LmotsAlgorithmType) -> HssKeyPair {
    let none_hasher: Option<Sha256Hasher> = None;
    super::custom::hss_keygen(lms_type, lmots_type, none_hasher)
}

#[cfg(test)]
mod tests {

    use super::*;

    #[test]
    fn test_signing() {
        let mut keys = hss_keygen(
            LmsAlgorithmType::LmsSha256M32H5,
            LmotsAlgorithmType::LmotsSha256N32W2,
        );

        let mut message = [
            32u8, 48, 2, 1, 48, 58, 20, 57, 9, 83, 99, 255, 0, 34, 2, 1, 0,
        ];

        let signature = hss_sign(&message, keys.private_key.get_mut_slice())
            .expect("Signing should complete without error.");

        assert!(hss_verify(
            &message,
            signature.get_slice(),
            keys.public_key.get_slice()
        ));

        message[0] = 33;

        assert!(hss_verify(&message, signature.get_slice(), keys.public_key.get_slice()) == false);
    }
}
