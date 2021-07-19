#![no_std]
#![allow(non_snake_case)]
#![allow(dead_code)]

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

pub use crate::hss::hss_keygen;
pub use crate::hss::hss_keygen_with_seed;
pub use crate::hss::hss_keygen_with_seed_and_aux;
pub use crate::hss::hss_sign;
pub use crate::hss::hss_verify;
