use crate::hasher::Hasher;

use super::{definitions::InMemoryHssPublicKey, signing::InMemoryHssSignature};

pub fn parse_public_key<'a, H: Hasher>(public_key: &'a [u8]) -> Option<InMemoryHssPublicKey<'a, H>> {
    InMemoryHssPublicKey::new(public_key)
}

pub fn parse_signature<'a, H: Hasher>(signature: &'a [u8]) -> Option<InMemoryHssSignature<'a, H>> {
    InMemoryHssSignature::new(signature)
}
