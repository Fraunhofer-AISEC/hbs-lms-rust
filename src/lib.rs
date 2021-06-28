#![no_std]

mod constants;
mod hasher;
mod hss;
mod lm_ots;
mod lms;
mod util;

pub use crate::lms::definitions::LmsAlgorithmType;

pub use crate::lm_ots::parameter::LmotsParameter;

pub use crate::lm_ots::parameter::LmotsSha256N32W1;
pub use crate::lm_ots::parameter::LmotsSha256N32W2;
pub use crate::lm_ots::parameter::LmotsSha256N32W4;
pub use crate::lm_ots::parameter::LmotsSha256N32W8;

pub use crate::hss::hss_keygen;
pub use crate::hss::hss_sign;
pub use crate::hss::hss_verify;
