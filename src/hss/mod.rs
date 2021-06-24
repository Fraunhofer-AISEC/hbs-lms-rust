use crate::{
    constants::{MAX_PRIVATE_KEY_LENGTH, MAX_PUBLIC_KEY_LENGTH, MAX_SIGNATURE_LENGTH},
    lms,
    util::{
        dynamic_array::DynamicArray,
        ustr::{str32u, u32str},
    },
    LmotsAlgorithmType, LmsAlgorithmType,
};

pub struct HssBinaryData {
    pub public_key: DynamicArray<u8, MAX_PUBLIC_KEY_LENGTH>,
    pub private_key: DynamicArray<u8, MAX_PRIVATE_KEY_LENGTH>,
}

pub fn hss_verify(message: &[u8], signature: &[u8], public_key: &[u8]) -> bool {
    // Todo: Check if HSS Levels = 1 and then forward data;

    if public_key.len() <= 4 {
        return false;
    }

    let hss_levels = str32u(&public_key[0..4]);

    // Needed to be compatible with reference implementation
    if hss_levels != 1 {
        panic!("HSS Levels greater than 1 are note supported yet.");
    }

    if signature.len() <= 4 {
        return false;
    }

    let signature_hss_levels = str32u(&signature[0..4]);

    // Needed to be compatible with reference implementation
    if signature_hss_levels != 0 {
        panic!("HSS Levels greater than 1 are note supported yet.")
    }

    crate::lms::verify(message, &signature[4..], &public_key[4..])
}

pub fn hss_sign(
    message: &[u8],
    private_key: &mut [u8],
) -> Option<DynamicArray<u8, MAX_SIGNATURE_LENGTH>> {
    let mut parsed_private_key =
        match lms::definitions::LmsPrivateKey::from_binary_representation(private_key) {
            None => return None,
            Some(x) => x,
        };

    let signature = lms::signing::LmsSignature::sign(&mut parsed_private_key, message);

    if signature.is_err() {
        return None;
    }

    // Replace private key with advanced key
    private_key.copy_from_slice(parsed_private_key.to_binary_representation().get_slice());

    let signature = signature.unwrap();

    let mut hss_signature = DynamicArray::new();
    let hss_levels = u32str(0); // Needed to be compatible with reference implementation

    hss_signature.append(&hss_levels);
    hss_signature.append(&signature.to_binary_representation().get_slice());

    Some(hss_signature)
}

pub fn hss_keygen(lms_type: LmsAlgorithmType, lmots_type: LmotsAlgorithmType) -> HssBinaryData {
    let private_key = crate::lms::generate_private_key(lms_type, lmots_type);
    let public_key = crate::lms::generate_public_key(&private_key);

    let private_key = private_key.to_binary_representation();
    let public_key = public_key.to_binary_representation();

    let mut hss_public_key = DynamicArray::new();
    let hss_levels = u32str(1); // Needed to be compatible with reference implementation

    hss_public_key.append(&hss_levels);
    hss_public_key.append(&public_key.get_slice());

    HssBinaryData {
        private_key,
        public_key: hss_public_key,
    }
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
