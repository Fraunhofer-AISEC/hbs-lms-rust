use crate::{
    definitions::{MAX_H, MAX_M, MAX_N, MAX_P, MAX_PRIV_KEY_LENGTH},
    lms,
    util::{
        helper::copy_and_advance,
        ustr::{str32u, u32str},
    },
    LmotsAlgorithmType, LmsAlgorithmType,
};

pub struct HssBinaryData {
    pub public_key: [u8; 4 + 4 + 4 + 16 + MAX_M],
    pub private_key: [u8; MAX_PRIV_KEY_LENGTH],
}

pub struct HssSignResult {
    pub advanced_private_key: [u8; MAX_PRIV_KEY_LENGTH],
    pub signature: [u8; 4 + 4 + (4 + MAX_N + (MAX_N * MAX_P)) + 4 + (MAX_M * MAX_H)],
}

pub fn hss_verify(message: &[u8], signature: &[u8], public_key: &[u8]) -> bool {
    // Todo: Check if HSS Levels = 1 and then forward data;

    assert!(public_key.len() > 4);
    let hss_levels = str32u(&public_key[0..4]);

    assert!(hss_levels == 1); // Needed to be compatible with reference implementation

    assert!(signature.len() > 4);
    let hss_levels = str32u(&signature[0..4]);

    assert!(hss_levels == 0); // Needed to be compatible with reference implementation

    crate::lms::verify(message, &signature[4..], &public_key[4..])
}

pub fn hss_sign(message: &[u8], private_key: &[u8]) -> Option<HssSignResult> {
    let mut private_key =
        match lms::definitions::LmsPrivateKey::from_binary_representation(private_key) {
            None => return None,
            Some(x) => x,
        };

    let public_key = lms::generate_public_key(&private_key);

    let signature = lms::signing::LmsSignature::sign(&mut private_key, &public_key, message);

    if signature.is_err() {
        return None;
    }

    let signature = signature.unwrap();

    let mut hss_signature = [0u8; 4 + 4 + (4 + MAX_N + (MAX_N * MAX_P)) + 4 + (MAX_M * MAX_H)];
    let hss_levels = u32str(0); // Needed to be compatible with reference implementation

    let mut hss_index = 0;

    copy_and_advance(&hss_levels, &mut hss_signature, &mut hss_index);
    copy_and_advance(
        &signature.to_binary_representation(),
        &mut hss_signature,
        &mut hss_index,
    );

    let result = HssSignResult {
        advanced_private_key: private_key.to_binary_representation(),
        signature: hss_signature,
    };

    Some(result)
}

pub fn hss_keygen(lms_type: LmsAlgorithmType, lmots_type: LmotsAlgorithmType) -> HssBinaryData {
    let private_key = crate::lms::generate_private_key(lms_type, lmots_type);
    let public_key = crate::lms::generate_public_key(&private_key);

    let private_key = private_key.to_binary_representation();
    let public_key = public_key.to_binary_representation();

    let mut hss_public_key = [0u8; 4 + 4 + 4 + 16 + MAX_M];
    let hss_levels = u32str(1); // Needed to be compatible with reference implementation

    let mut hss_index = 0;

    copy_and_advance(&hss_levels, &mut hss_public_key, &mut hss_index);
    copy_and_advance(&public_key, &mut hss_public_key, &mut hss_index);

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
        let keys = hss_keygen(
            LmsAlgorithmType::LmsSha256M32H5,
            LmotsAlgorithmType::LmotsSha256N32W2,
        );

        let mut message = [
            32u8, 48, 2, 1, 48, 58, 20, 57, 9, 83, 99, 255, 0, 34, 2, 1, 0,
        ];

        let signature = hss_sign(&message, &keys.private_key)
            .expect("Signing should complete without error.")
            .signature;

        assert!(hss_verify(&message, &signature, &keys.public_key));

        message[0] = 33;

        assert!(hss_verify(&message, &signature, &keys.public_key) == false);
    }
}
