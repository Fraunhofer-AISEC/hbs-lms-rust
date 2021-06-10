use crate::{
    lms,
    util::ustr::{str32u, u32str},
    LmotsAlgorithmType, LmsAlgorithmType,
};

pub struct HssBinaryData {
    pub public_key: Vec<u8>,
    pub private_key: Vec<u8>,
}

pub struct HssSignResult {
    pub advanced_private_key: Vec<u8>,
    pub signature: Vec<u8>,
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

    let mut hss_signature: Vec<u8> = Vec::new();
    let hss_levels = u32str(0); // Needed to be compatible with reference implementation

    hss_signature.extend(hss_levels.iter());
    hss_signature.extend(signature.to_binary_representation());

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

    let mut hss_public_key: Vec<u8> = Vec::new();
    let hss_levels = u32str(1); // Needed to be compatible with reference implementation

    hss_public_key.extend(hss_levels.iter());
    hss_public_key.extend(public_key);

    HssBinaryData {
        private_key,
        public_key: hss_public_key,
    }
}
