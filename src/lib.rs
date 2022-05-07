#![forbid(unsafe_code)]
#![cfg_attr(not(feature = "std"), no_std)]

//! This library implements the Leighton-Micali-Signature scheme, as defined in the
//! [RFC 8554](<https://datatracker.ietf.org/doc/html/rfc8554>).
//!
//! It is a post-quantum secure algorithm that can be used to
//! generate digital signatures. NIST has published recommendations for this algorithm in:
//! [NIST Recommendations for Stateful Hash-Based Signatures](https://doi.org/10.6028/NIST.SP.800-208)
//!
//! This crate can be used together with the [`signature::SignerMut`] and [`signature::Verifier`] traits.
//!
//! # Example
//! ```
//! use rand::{rngs::OsRng, RngCore};
//! use hbs_lms::{keygen, HssParameter, LmotsAlgorithm, LmsAlgorithm,
//!     Signature, signature::{SignerMut, Verifier},
//!     Sha256, Seed,
//! };
//!
//! let message: [u8; 7] = [42, 84, 34, 12, 64, 34, 32];
//!
//! // Generate keys for a 2-level HSS system (RootTree W1/H5, ChildTree W2/H5)
//! let hss_parameter = [
//!         HssParameter::<Sha256>::new(LmotsAlgorithm::LmotsW1, LmsAlgorithm::LmsH5),
//!         HssParameter::<Sha256>::new(LmotsAlgorithm::LmotsW2, LmsAlgorithm::LmsH5),
//! ];
//!
//! let mut seed = Seed::default();
//! OsRng.fill_bytes(&mut seed);
//! let aux_data = None;
//!
//! let (mut signing_key, verifying_key) =
//!     hbs_lms::keygen::<Sha256>(&hss_parameter, &seed, aux_data).unwrap();
//!
//! let signature = signing_key.try_sign(&message).unwrap();
//!
//!
//! let valid_signature = verifying_key.verify(&message, &signature);
//!
//! assert_eq!(valid_signature.is_ok(), true);
//! ```
//!
//! # Environment Variables
//!
//! To adapt the internals of the crate, the user can set the following environment variables:
//!
//! ## Adapting the crate in general
//!
//! These three environment variables listed below, adapt the internals of the crate and can be used
//! to reduce the required stack size. The values are used to set the maximum size of the arrays
//! used for computation and storing intermediate values.
//!
//! Any change limits the functionality of this crate, as no longer all possible parameters are
//! supported! (For example setting `HBS_LMS_MAX_ALLOWED_HSS_LEVELS` to 1 allows only for a single
//! tree.)
//!
//! The length of the tree height and the winternitz parameter arrays must match the value of the
//! HSS levels.
//!
//! | Name                           | Default | Range of Values    | Description             |
//! |--------------------------------|---------|--------------------|-------------------------|
//! | HBS_LMS_MAX_ALLOWED_HSS_LEVELS | 8       | 1..8               | Max. tree count for HSS |
//! | HBS_LMS_TREE_HEIGHTS           | [25; 8] | [`LmsAlgorithm`]   | Max. Tree Height for each tree|
//! | HBS_LMS_WINTERNITZ_PARAMETERS  | [1; 8]  | [`LmotsAlgorithm`] | Min. Winternitz Parameter for each tree |
//!
//! Reducing the HSS levels or the values of the tree heights lead to a reduced stack usage. For the
//! values of the Winternitz parameter the inverse must be applied, as higher Winternitz parameters
//! reduce the stack usage.
//!
//! ## Adapting wrt the 'fast_verify' feature
//!
//! The 'fast_verify' features enables this crate to sign fast verifiable signatures. The drawback
//! is more computative effort on the side of the signer. With the these two environment variables
//! listed below, the user can adapt effect.
//!
//! | Name                           | Default | Description                      |
//! |--------------------------------|---------|----------------------------------|
//! | HBS_LMS_MAX_HASH_OPTIMIZATIONS | 10_000  | Try count to optimize the hash   |
//! | HBS_LMS_THREADS                | 1       | Thread count to split the effort |
//!
//! If the crate is compiled with the std library, the effort of the generation of fast verifiable
//! signatures can be split to multiple threads using the `HBS_LMS_THREADS`.

mod constants;
mod hasher;
mod hss;
mod lm_ots;
mod lms;
mod util;

// Re-export the `signature` crate
pub use signature::{self};

#[doc(hidden)]
pub use crate::constants::{Seed, MAX_HASH_SIZE};

pub use crate::hasher::{sha256::Sha256, shake256::Shake256, HashChain, HashChainData};

pub use crate::hss::parameter::HssParameter;
pub use crate::lm_ots::parameters::LmotsAlgorithm;
pub use crate::lms::parameters::LmsAlgorithm;

pub use crate::hss::hss_keygen as keygen;
pub use crate::hss::hss_sign as sign;
#[cfg(feature = "fast_verify")]
pub use crate::hss::hss_sign_mut as sign_mut;
pub use crate::hss::hss_verify as verify;
pub use crate::hss::{SigningKey, VerifyingKey};

use core::convert::TryFrom;
use signature::Error;
use tinyvec::TinyVec;

use constants::MAX_HSS_SIGNATURE_LENGTH;

/**
 * Implementation of [`signature::Signature`].
 */
#[derive(Debug)]
pub struct Signature {
    bytes: TinyVec<[u8; MAX_HSS_SIGNATURE_LENGTH]>,
    #[cfg(feature = "verbose")]
    pub hash_iterations: u32,
}

impl Signature {
    pub(crate) fn from_bytes_verbose(bytes: &[u8], _hash_iterations: u32) -> Result<Self, Error> {
        let bytes = TinyVec::try_from(bytes).map_err(|_| Error::new())?;

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

/**
 * No-copy friendly alternative to [`Signature`] by using a reference to a slice of bytes (for
 * verification only!).
 */
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
    use crate::{keygen, HssParameter, LmotsAlgorithm, LmsAlgorithm, Seed, Sha256};
    use crate::{
        signature::{SignerMut, Verifier},
        SigningKey, VerifierSignature, VerifyingKey,
    };

    use rand::{rngs::OsRng, RngCore};

    #[test]
    fn get_signing_and_verifying_key() {
        type H = Sha256;
        let mut seed = Seed::default();
        OsRng.fill_bytes(&mut seed);

        let (mut signing_key, verifying_key) = keygen::<H>(
            &[HssParameter::new(
                LmotsAlgorithm::LmotsW2,
                LmsAlgorithm::LmsH5,
            )],
            &seed,
            None,
        )
        .expect("Should work and not overflow");

        let message: [u8; 7] = [42, 84, 34, 12, 64, 34, 32];

        signing_key.try_sign(&message).unwrap();

        let _: SigningKey<H> = signing_key;
        let _: VerifyingKey<H> = verifying_key;
    }

    #[test]
    fn signature_trait() {
        let message = [
            32u8, 48, 2, 1, 48, 58, 20, 57, 9, 83, 99, 255, 0, 34, 2, 1, 0,
        ];
        let mut seed = Seed::default();
        OsRng.fill_bytes(&mut seed);

        let (mut signing_key, verifying_key) = keygen::<Sha256>(
            &[
                HssParameter::new(LmotsAlgorithm::LmotsW2, LmsAlgorithm::LmsH5),
                HssParameter::new(LmotsAlgorithm::LmotsW2, LmsAlgorithm::LmsH5),
            ],
            &seed,
            None,
        )
        .unwrap();

        let signature = signing_key.try_sign(&message).unwrap();

        assert!(verifying_key.verify(&message, &signature).is_ok());

        let ref_signature = VerifierSignature::from_ref(signature.as_ref()).unwrap();

        assert!(verifying_key.verify(&message, &ref_signature).is_ok());
    }
}
