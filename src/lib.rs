#![cfg_attr(not(feature = "std"), no_std)]

//! This library implements the Leighton-Micali-Signature scheme <https://datatracker.ietf.org/doc/html/rfc8554>
//!
//! # Example
//! ```
//! use hbs_lms::*;
//!
//! let message: [u8; 7] = [42, 84, 34, 12, 64, 34, 32]; // Some message that needs to be signed
//!
//! // Generate keys for a 2-level HSS system (first Level W8/H5, second level W4/H15) using the standard software hashing implementation
//! let key_pair = hbs_lms::keygen::<Sha256Hasher>(&[HssParameter::new(LmotsAlgorithm::LmotsW8, LmsAlgorithm::LmsH5), HssParameter::new(LmotsAlgorithm::LmotsW4, LmsAlgorithm::LmsH5)], None, None).unwrap();
//!
//! let private_key = key_pair.get_private_key();
//! let public_key = key_pair.get_public_key();
//!
//! let mut private_key_update_function = |new_private_key: &[u8]| {
//!     // Update private key and save it to disk
//!     true // Report successful result
//! };
//!
//! let sig = hbs_lms::sign::<Sha256Hasher>(&message, private_key, &mut private_key_update_function, None).unwrap();
//! let sig_slice = sig.as_slice();
//!
//! let verify_result = hbs_lms::verify::<Sha256Hasher>(&message, sig_slice, public_key);
//!
//! assert!(verify_result == true);
//! ```

mod constants;
mod hasher;
mod hss;
mod lm_ots;
mod lms;
mod util;

pub use hasher::Hasher;

#[doc(hidden)]
pub use crate::constants::Seed;

pub use crate::hasher::sha256::Sha256Hasher;

pub use crate::hss::parameter::HssParameter;
pub use crate::lm_ots::parameters::LmotsAlgorithm;
pub use crate::lms::parameters::LmsAlgorithm;

pub use crate::hss::HssKeyPair;

pub use crate::hss::hss_keygen as keygen;
pub use crate::hss::hss_sign as sign;
#[cfg(feature = "fast_verify")]
pub use crate::hss::hss_sign_mut as sign_mut;
pub use crate::hss::hss_verify as verify;
