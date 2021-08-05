#![cfg_attr(not(feature = "std"), no_std)]
#![allow(non_snake_case)]

mod constants;
pub mod hasher;
mod hss;
mod lm_ots;
mod lms;
mod util;

use hasher::Hasher;
use hss::definitions::HssPrivateKey;
use hss::rfc_private_key::RfcPrivateKey;

pub use crate::constants::Seed;
pub use crate::hasher::sha256::Sha256Hasher;
pub use crate::hss::parameter::HssParameter;
pub use crate::lm_ots::parameters::*;
pub use crate::lms::parameters::*;

pub use crate::util::dynamic_array::DynamicArray;

pub use crate::hss::definitions::HssPublicKey;
pub use crate::hss::definitions::InMemoryHssPublicKey;
pub use crate::hss::signing::InMemoryHssSignature;

pub use crate::hss::hss_keygen;
pub use crate::hss::hss_sign;
pub use crate::hss::hss_verify;

pub fn get_public_key<H: Hasher>(private_key: &[u8]) -> Option<HssPublicKey<H>> {
    let rfc_private_key = RfcPrivateKey::<H>::from_binary_representation(private_key)?;
    let hss_private_key = HssPrivateKey::from(&rfc_private_key, None).ok()?;
    Some(hss_private_key.get_public_key())
}
