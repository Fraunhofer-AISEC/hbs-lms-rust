use crate::{hasher::Hasher};

use super::{definitions::HssPublicKey, signing::HssSignature};

pub fn parse_public_key<H: Hasher, const L: usize>(
    public_key: &[u8],
) -> Option<HssPublicKey<H, L>> {
    HssPublicKey::from_binary_representation(public_key)
}

pub fn parse_signature<H: Hasher, const L: usize>(
    signature: &[u8],
) -> Option<HssSignature<H, L>> {
    HssSignature::from_binary_representation(signature)
}
