use crate::hasher::Hasher;

use super::{definitions::InMemoryHssPublicKey, signing::InMemoryHssSignature};

pub fn parse_public_key<H: Hasher>(public_key: &[u8]) -> Option<InMemoryHssPublicKey<H>> {
    InMemoryHssPublicKey::new(public_key)
}

pub fn parse_signature<H: Hasher>(signature: &[u8]) -> Option<InMemoryHssSignature<H>> {
    InMemoryHssSignature::new(signature)
}
