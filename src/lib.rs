#![cfg_attr(not(feature = "std"), no_std)]

//! This library implements the Leighton-Micali-Signature scheme <https://datatracker.ietf.org/doc/html/rfc8554>
//!
//! # Example
//! ```
//! use hbs_lms::{keygen, HssParameter, LmotsAlgorithm, LmsAlgorithm,
//!     Signature, signature::{SignerMut, Verifier},
//!     Sha256Hasher,
//! };
//!
//! let message: [u8; 7] = [42, 84, 34, 12, 64, 34, 32];
//!
//! // Generate keys for a 2-level HSS system (RootTree W1/H5, ChildTree W2/H5)
//! let hss_parameter = [
//!         HssParameter::<Sha256Hasher>::new(LmotsAlgorithm::LmotsW1, LmsAlgorithm::LmsH5),
//!         HssParameter::<Sha256Hasher>::new(LmotsAlgorithm::LmotsW2, LmsAlgorithm::LmsH5),
//! ];
//! let seed = None;
//! let aux_data = None;
//!
//! let (mut signing_key, verifying_key) =
//!     hbs_lms::keygen::<Sha256Hasher>(&hss_parameter, seed, aux_data).unwrap();
//!
//! let signature = signing_key.try_sign(&message).unwrap();
//!
//! let valid_signature = verifying_key.verify(&message, &signature);
//!
//! assert_eq!(valid_signature.is_ok(), true);
//! ```

mod constants;
mod hasher;
mod hss;
mod lm_ots;
mod lms;
mod util;

// Re-export the `signature` crate
pub use signature::{self};

#[doc(hidden)]
pub use crate::constants::Seed;

pub use crate::hasher::{sha256::Sha256Hasher, shake256::Shake256Hasher, Hasher};

pub use crate::hss::parameter::HssParameter;
pub use crate::lm_ots::parameters::LmotsAlgorithm;
pub use crate::lms::parameters::LmsAlgorithm;

pub use crate::hss::hss_keygen as keygen;
pub use crate::hss::hss_sign as sign;
#[cfg(feature = "fast_verify")]
pub use crate::hss::hss_sign_mut as sign_mut;
pub use crate::hss::hss_verify as verify;
pub use crate::hss::{SigningKey, VerifyingKey};

use arrayvec::ArrayVec;
use core::convert::TryFrom;
use signature::Error;

use constants::MAX_HSS_SIGNATURE_LENGTH;

#[derive(Debug)]
pub struct Signature {
    bytes: ArrayVec<u8, MAX_HSS_SIGNATURE_LENGTH>,
    #[cfg(feature = "verbose")]
    pub hash_iterations: u32,
}

impl Signature {
    pub(crate) fn from_bytes_verbose(bytes: &[u8], _hash_iterations: u32) -> Result<Self, Error> {
        let bytes = ArrayVec::try_from(bytes).map_err(|_| Error::new())?;

        Ok(Self {
            bytes,
            #[cfg(feature = "verbose")]
            hash_iterations: _hash_iterations,
        })
    }
}

impl AsRef<[u8]> for Signature {
    fn as_ref(&self) -> &[u8] {
        self.bytes.as_ref()
    }
}

impl signature::Signature for Signature {
    fn from_bytes(bytes: &[u8]) -> Result<Self, Error> {
        Signature::from_bytes_verbose(bytes, 0)
    }
}

#[derive(Debug)]
pub struct VerifierSignature<'a> {
    bytes: &'a [u8],
}

#[allow(dead_code)]
impl<'a> VerifierSignature<'a> {
    pub fn from_ref(bytes: &'a [u8]) -> Result<Self, Error> {
        Ok(Self { bytes })
    }
}

impl<'a> AsRef<[u8]> for VerifierSignature<'a> {
    fn as_ref(&self) -> &'a [u8] {
        self.bytes
    }
}

impl<'a> signature::Signature for VerifierSignature<'a> {
    fn from_bytes(_bytes: &[u8]) -> Result<Self, Error> {
        Err(Error::new())
    }
}

#[cfg(test)]
mod tests {
    use crate::{keygen, HssParameter, LmotsAlgorithm, LmsAlgorithm, Sha256Hasher};
    use crate::{
        signature::{SignerMut, Verifier},
        SigningKey, VerifierSignature, VerifyingKey,
    };

    #[test]
    fn get_signing_and_verifying_key() {
        type H = Sha256Hasher;

        let (signing_key, verifying_key) = keygen::<H>(
            &[HssParameter::new(
                LmotsAlgorithm::LmotsW2,
                LmsAlgorithm::LmsH5,
            )],
            None,
            None,
        )
        .unwrap();

        let _: SigningKey<H> = signing_key;
        let _: VerifyingKey<H> = verifying_key;
    }

    #[test]
    fn signature_trait() {
        let message = [
            32u8, 48, 2, 1, 48, 58, 20, 57, 9, 83, 99, 255, 0, 34, 2, 1, 0,
        ];

        let (mut signing_key, verifying_key) = keygen::<Sha256Hasher>(
            &[
                HssParameter::new(LmotsAlgorithm::LmotsW2, LmsAlgorithm::LmsH5),
                HssParameter::new(LmotsAlgorithm::LmotsW2, LmsAlgorithm::LmsH5),
            ],
            None,
            None,
        )
        .unwrap();

        let signature = signing_key.try_sign(&message).unwrap();

        assert!(verifying_key.verify(&message, &signature).is_ok());

        let ref_signature = VerifierSignature::from_ref(signature.as_ref()).unwrap();

        assert!(verifying_key.verify(&message, &ref_signature).is_ok());
    }
}
