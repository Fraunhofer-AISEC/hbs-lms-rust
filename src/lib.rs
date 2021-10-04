#![cfg_attr(not(feature = "std"), no_std)]

mod constants;
pub mod hasher;
mod hss;
mod lm_ots;
mod lms;
mod util;

pub use hasher::Hasher;

pub use crate::constants::Seed;
pub use crate::hasher::sha256::Sha256Hasher;

pub use crate::hss::parameter::HssParameter;
pub use crate::lm_ots::parameters::*;
pub use crate::lms::parameters::*;

pub use crate::hss::HssKeyPair;

pub use crate::util::dynamic_array::DynamicArray;

pub use crate::hss::hss_keygen as keygen;
pub use crate::hss::hss_sign as sign;
pub use crate::hss::hss_verify as verify;
