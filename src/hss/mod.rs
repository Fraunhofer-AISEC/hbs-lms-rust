pub mod aux;
pub mod definitions;
pub mod parameter;
pub mod reference_impl_private_key;
mod seed_derive;
pub mod signing;
pub mod verify;

use arrayvec::ArrayVec;

use crate::{
    constants::{MAX_HASH_SIZE, MAX_HSS_SIGNATURE_LENGTH, REFERENCE_IMPL_PRIVATE_KEY_SIZE},
    extract_or, extract_or_return,
    hasher::Hasher,
    hss::{definitions::InMemoryHssPublicKey, signing::InMemoryHssSignature},
};

use self::{
    definitions::HssPrivateKey, parameter::HssParameter,
    reference_impl_private_key::ReferenceImplPrivateKey, signing::HssSignature,
};

/**
 * Describes a public and private key.
 * */
pub struct HssKeyPair {
    pub public_key: ArrayVec<u8, { 4 + 4 + 4 + 16 + MAX_HASH_SIZE }>,
    pub private_key: ArrayVec<u8, REFERENCE_IMPL_PRIVATE_KEY_SIZE>,
}

impl HssKeyPair {
    fn new(
        public_key: ArrayVec<u8, { 4 + 4 + 4 + 16 + MAX_HASH_SIZE }>,
        private_key: ArrayVec<u8, REFERENCE_IMPL_PRIVATE_KEY_SIZE>,
    ) -> Self {
        Self {
            public_key,
            private_key,
        }
    }

    pub fn get_public_key(&self) -> &[u8] {
        self.public_key.as_slice()
    }

    pub fn get_private_key(&self) -> &[u8] {
        self.private_key.as_slice()
    }
}

/**
 * This function is used to verify a signature.
 *
 * # Arguments
 * * `Hasher` - The hasher implementation that should be used. ```Sha256Hasher``` is a standard software implementation.
 * * `message` - The message that should be verified.
 * * `signature` - The signature that should be used for verification.
 * * `public_key` - The public key that should be used for verification.
 */
pub fn hss_verify<H: Hasher>(message: &[u8], signature: &[u8], public_key: &[u8]) -> bool {
    let signature = extract_or!(InMemoryHssSignature::<H>::new(signature), false);
    let public_key = extract_or!(InMemoryHssPublicKey::<H>::new(public_key), false);

    crate::hss::verify::verify(&signature, &public_key, message).is_ok()
}

/**
 * This function is used to generate a signature.
 *
 * # Arguments
 * * `Hasher` - The hasher implementation that should be used. ```Sha256Hasher``` is a standard software implementation.
 * * `message` - The message that should be signed.
 * * `private_key` - The private key that should be used.
 * * `private_key_update_function` - The update function that is called with the new private key. This function should save the new private key.
 * * `aux_data` - Auxiliary data to speedup signature generation if available
 */
pub fn hss_sign<H: 'static + Hasher>(
    message: &mut [u8],
    private_key: &[u8],
    private_key_update_function: &mut dyn FnMut(&[u8]) -> bool,
    aux_data: Option<&mut &mut [u8]>,
) -> Option<ArrayVec<u8, MAX_HSS_SIGNATURE_LENGTH>> {
    let mut rfc_private_key = extract_or_return!(
        ReferenceImplPrivateKey::from_binary_representation(private_key)
    );

    let mut parsed_private_key: HssPrivateKey<H> =
        match HssPrivateKey::from(&rfc_private_key, aux_data) {
            Ok(x) => x,
            Err(_) => return None,
        };

    let signature = match HssSignature::sign(&mut parsed_private_key, message, message_mut) {
        Err(_) => return None,
        Ok(x) => x,
    };

    // Advance private key
    rfc_private_key.lms_leaf_identifier += 1;
    let updated_key = rfc_private_key.to_binary_representation();
    let update_successful = private_key_update_function(updated_key.as_slice());

    if update_successful {
        Some(signature.to_binary_representation())
    } else {
        None
    }
}

/**
 * This function is used to generate a public and private key.
 * # Arguments
 *
 * * `Hasher` - The hasher implementation that should be used. ```Sha256Hasher``` is a standard software implementation.
 * * `parameters` - An array which specifies the Winternitz parameter and tree height of each individual HSS level. The first element describes Level 1, the second element Level 2 and so on.
 * * `seed` - An optional seed which will be used to generate the private key. It must be only used for testing purposes and not for production used key pairs.
 * * `aux_data` - The reference to a slice to auxiliary data. This can be used to speedup signature generation.
 *
 * # Example
 * ```
 * use hbs_lms::*;
 *
 * let parameters = [HssParameter::new(LmotsAlgorithm::LmotsW4, LmsAlgorithm::LmsH5), HssParameter::new(LmotsAlgorithm::LmotsW1, LmsAlgorithm::LmsH5)];
 * let mut aux_data = vec![0u8; 10_000];
 * let aux_slice: &mut &mut [u8] = &mut &mut aux_data[..];
 *
 * let key_pair = keygen::<Sha256Hasher>(&parameters, None, Some(aux_slice));
 * ```
 */
pub fn hss_keygen<H: 'static + Hasher>(
    parameters: &[HssParameter<H>],
    seed: Option<&[u8]>,
    aux_data: Option<&mut &mut [u8]>,
) -> Option<HssKeyPair> {
    let private_key = if let Some(seed) = seed {
        ReferenceImplPrivateKey::generate_with_seed(parameters, seed)
    } else {
        ReferenceImplPrivateKey::generate(parameters)
    };

    if let Some(private_key) = private_key {
        let hss_key: HssPrivateKey<H> = match HssPrivateKey::from(&private_key, aux_data) {
            Err(_) => return None,
            Ok(x) => x,
        };
        Some(HssKeyPair::new(
            hss_key.get_public_key().to_binary_representation(),
            private_key.to_binary_representation(),
        ))
    } else {
        None
    }
}

#[cfg(test)]
mod tests {

    use crate::hasher::sha256::Sha256Hasher;

    use super::*;

    #[test]
    fn test_signing() {
        type H = Sha256Hasher;

        let mut keypair = hss_keygen::<H>(
            &[
                HssParameter::construct_default_parameters(),
                HssParameter::construct_default_parameters(),
                HssParameter::construct_default_parameters(),
            ],
            None,
            None,
        )
        .expect("Should generate HSS keys");

        let message_values = [
            32u8, 48, 2, 1, 48, 58, 20, 57, 9, 83, 99, 255, 0, 34, 2, 1, 0,
        ];
        let mut message = [0u8; 64];
        message[..message_values.len()].copy_from_slice(&message_values);

        let private_key = keypair.private_key.clone();

        let mut update_private_key = |new_key: &[u8]| {
            keypair.private_key.as_mut_slice().copy_from_slice(new_key);
            true
        };

        let signature = hss_sign::<H>(
            &mut message,
            private_key.as_slice(),
            &mut update_private_key,
            None,
        )
        .expect("Signing should complete without error.");

        assert!(hss_verify::<H>(
            &message,
            signature.as_slice(),
            keypair.public_key.as_slice()
        ));

        message[0] = 33;

        assert!(!hss_verify::<H>(
            &message,
            signature.as_slice(),
            keypair.public_key.as_slice()
        ));
    }

    #[cfg(feature = "fast_verify")]
    #[test]
    fn test_signing_fast_verify() {
        type H = Sha256Hasher;

        let mut keypair = hss_keygen::<H>(
            &[
                HssParameter::construct_default_parameters(),
                HssParameter::construct_default_parameters(),
                HssParameter::construct_default_parameters(),
            ],
            None,
            None,
        )
        .expect("Should generate HSS keys");

        let message_values = [
            32u8, 48, 2, 1, 48, 58, 20, 57, 9, 83, 99, 255, 0, 34, 2, 1, 0,
        ];
        let mut message = [0u8; 64];
        message[..message_values.len()].copy_from_slice(&message_values);

        let private_key = keypair.private_key.clone();

        let mut update_private_key = |new_key: &[u8]| {
            keypair.private_key.as_mut_slice().copy_from_slice(new_key);
            true
        };

        let signature = hss_sign::<H>(
            &mut message,
            private_key.as_slice(),
            &mut update_private_key,
            None,
        )
        .expect("Signing should complete without error.");

        assert!(H::OUTPUT_SIZE == MAX_HASH_SIZE as u16);
        assert_ne!(
            message[(message.len() - MAX_HASH_SIZE)..],
            [0u8; MAX_HASH_SIZE]
        );

        assert!(hss_verify::<H>(
            &message,
            signature.as_slice(),
            keypair.public_key.as_slice()
        ));
    }
}
