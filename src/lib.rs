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
//! let (signing_key, verifying_key) = hbs_lms::keygen::<Sha256Hasher>(&[HssParameter::new(LmotsAlgorithm::LmotsW8, LmsAlgorithm::LmsH5), HssParameter::new(LmotsAlgorithm::LmotsW4, LmsAlgorithm::LmsH5)], None, None).unwrap();
//!
//! let mut private_key_update_function = |new_private_key: &[u8]| {
//!     // Update private key and save it to disk
//!     Ok(()) // Report successful result
//! };
//!
//! let sig = hbs_lms::sign::<Sha256Hasher>(&message, signing_key.as_slice(), &mut private_key_update_function, None).unwrap();
//! let sig_ref = sig.as_ref();
//!
//! let verify_result = hbs_lms::verify::<Sha256Hasher>(&message, sig_ref, verifying_key.as_slice());
//!
//! assert!(verify_result == true);
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
pub use crate::hss::hss_lifetime as lifetime;
pub use crate::hss::hss_sign as sign;
#[cfg(feature = "fast_verify")]
pub use crate::hss::hss_sign_mut as sign_mut;
pub use crate::hss::hss_verify as verify;
pub use crate::hss::{SigningKey, VerifyingKey};

use arrayvec::ArrayVec;
use core::{convert::TryFrom, marker::PhantomData};
use signature::Error;

use constants::MAX_HSS_SIGNATURE_LENGTH;

#[derive(Debug)]
pub struct Signature<H: Hasher> {
    bytes: ArrayVec<u8, MAX_HSS_SIGNATURE_LENGTH>,
    phantom_data: PhantomData<H>,
    #[cfg(feature = "verbose")]
    pub hash_iterations: u32,
}

impl<H: Hasher> Signature<H> {
    pub(crate) fn from_bytes_verbose(bytes: &[u8], _hash_iterations: u32) -> Result<Self, Error> {
        let bytes = ArrayVec::try_from(bytes).map_err(|_| Error::new())?;

        Ok(Self {
            bytes,
            phantom_data: PhantomData,
            #[cfg(feature = "verbose")]
            hash_iterations: _hash_iterations,
        })
    }
}

impl<H: Hasher> AsRef<[u8]> for Signature<H> {
    fn as_ref(&self) -> &[u8] {
        self.bytes.as_ref()
    }
}

impl<H: Hasher> signature::Signature for Signature<H> {
    fn from_bytes(bytes: &[u8]) -> Result<Self, Error> {
        Signature::from_bytes_verbose(bytes, 0)
    }
}

#[derive(Debug)]
pub struct VerifierSignature<'a, H: Hasher> {
    bytes: &'a [u8],
    phantom_data: PhantomData<H>,
}

#[allow(dead_code)]
impl<'a, H: Hasher> VerifierSignature<'a, H> {
    pub fn from_ref(bytes: &'a [u8]) -> Result<Self, Error> {
        Ok(Self {
            bytes,
            phantom_data: PhantomData,
        })
    }
}

impl<'a, H: Hasher> AsRef<[u8]> for VerifierSignature<'a, H> {
    fn as_ref(&self) -> &'a [u8] {
        self.bytes
    }
}

impl<'a, H: Hasher> signature::Signature for VerifierSignature<'a, H> {
    fn from_bytes(_bytes: &[u8]) -> Result<Self, Error> {
        Err(Error::new())
    }
}

#[cfg(test)]
mod tests {
    use crate::{keygen, HssParameter, LmotsAlgorithm, LmsAlgorithm, Sha256Hasher};
    use crate::{
        signature::{SignerMut, Verifier},
        Signature, SigningKey, VerifierSignature, VerifyingKey,
    };

    #[test]
    fn get_signing_and_verifying_key() {
        let (signing_key, verifying_key) = keygen::<Sha256Hasher>(
            &[HssParameter::new(
                LmotsAlgorithm::LmotsW2,
                LmsAlgorithm::LmsH5,
            )],
            None,
            None,
        )
        .unwrap();

        let _: SigningKey = signing_key;
        let _: VerifyingKey = verifying_key;
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

        let signature: Signature<Sha256Hasher> = signing_key.try_sign(&message).unwrap();

        assert!(verifying_key.verify(&message, &signature).is_ok());

        let ref_signature =
            VerifierSignature::<Sha256Hasher>::from_ref(signature.as_ref()).unwrap();

        assert!(verifying_key.verify(&message, &ref_signature).is_ok());
    }
}
