use crate::{LmotsParameter, LmsParameter};

use super::{definitions::HssPublicKey, signing::HssSignature};

pub fn parse_public_key<OTS: LmotsParameter, LMS: LmsParameter, const L: usize>(
    public_key: &[u8],
) -> Option<HssPublicKey<OTS, LMS, L>> {
    HssPublicKey::<OTS, LMS, L>::from_binary_representation(public_key)
}

pub fn parse_signature<OTS: LmotsParameter, LMS: LmsParameter, const L: usize>(
    signature: &[u8],
) -> Option<HssSignature<OTS, LMS, L>> {
    HssSignature::<OTS, LMS, L>::from_binary_representation(signature)
}
