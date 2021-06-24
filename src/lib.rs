#![no_std]

mod constants;
mod hasher;
mod hss;
mod lm_ots;
mod lms;
mod util;

pub use crate::lm_ots::definitions::LmotsAlgorithmType;
pub use crate::lms::definitions::LmsAlgorithmType;

pub use crate::hss::standard::hss_keygen;
pub use crate::hss::standard::hss_sign;
pub use crate::hss::standard::hss_verify;

pub use crate::hss::custom::hss_keygen as hss_keygen_with_custom_functions;
pub use crate::hss::custom::hss_sign as hss_sign_with_custom_functions;
pub use crate::hss::custom::hss_verify as hss_verify_with_custom_functions;
