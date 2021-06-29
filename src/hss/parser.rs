use crate::{LmotsParameter, LmsParameter, LmsPublicKey, LmsSignature, util::ustr::str32u};

pub fn parse_public_key<OTS: LmotsParameter, LMS: LmsParameter>(public_key: &[u8]) -> Option<LmsPublicKey<OTS, LMS>> {

    if public_key.len() <= 4 {
        return None;
    }

    let hss_levels = str32u(&public_key[0..4]);

    // Needed to be compatible with reference implementation
    if hss_levels != 1 {
        return None;
    }

    LmsPublicKey::<OTS, LMS>::from_binary_representation(&public_key[4..])
}

pub fn parse_signature<OTS: LmotsParameter, LMS: LmsParameter>(signature: &[u8]) -> Option<LmsSignature<OTS, LMS>> {

    if signature.len() <= 4 {
        return None;
    }

    let signature_hss_levels = str32u(&signature[0..4]);

    // Needed to be compatible with reference implementation
    if signature_hss_levels != 0 {
        return None;
    }

    LmsSignature::<OTS, LMS>::from_binary_representation(&signature[4..])
}

