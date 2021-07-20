#![no_std]
#![allow(non_snake_case)]

mod constants;
mod hasher;
mod hss;
mod lm_ots;
mod lms;
mod util;

pub use crate::constants::Seed;
pub use crate::hasher::sha256::Sha256Hasher;
pub use crate::hss::parameter::HssParameter;
pub use crate::lm_ots::parameters::*;
pub use crate::lms::parameters::*;

pub use crate::hss::definitions::HssPublicKey;
pub use crate::hss::signing::HssSignature;

pub use crate::hss::hss_keygen;
pub use crate::hss::hss_sign;
pub use crate::hss::hss_verify;

pub use crate::hss::parser::parse_public_key as hss_parse_public_key;
pub use crate::hss::parser::parse_signature as hss_parse_signature;
