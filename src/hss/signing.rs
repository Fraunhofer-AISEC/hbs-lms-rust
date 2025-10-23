use crate::{
    constants::{
        lms_public_key_length, lms_signature_length, MAX_ALLOWED_HSS_LEVELS,
        MAX_HSS_SIGNATURE_LENGTH, MAX_HSS_SIGNED_PUBLIC_KEY_LENGTH,
    },
    hss::{
        aux::MutableExpandedAuxData,
        reference_impl_private_key::{generate_signature_randomizer, SeedAndLmsTreeIdentifier},
    },
    lms::{
        self,
        definitions::{InMemoryLmsPublicKey, LmsPublicKey},
        signing::{InMemoryLmsSignature, LmsSignature},
    },
    util::helper::read_and_advance,
    HashChain,
};

use super::definitions::HssPrivateKey;

use core::convert::TryInto;
use tinyvec::ArrayVec;

#[derive(PartialEq)]
pub struct HssSignature<H: HashChain> {
    pub level: usize,
    pub signed_public_keys: ArrayVec<[HssSignedPublicKey<H>; MAX_ALLOWED_HSS_LEVELS - 1]>,
    pub signature: LmsSignature<H>,
}

impl<H: HashChain> HssSignature<H> {
    pub fn sign(
        private_key: &mut HssPrivateKey<H>,
        message: Option<&[u8]>,
        message_mut: Option<&mut [u8]>,
        aux_data: &mut Option<MutableExpandedAuxData>,
    ) -> Result<HssSignature<H>, ()> {
        let max_level = private_key.get_length();

        let prv = &mut private_key.private_key;
        let public = &mut private_key.public_key;
        let sig = &mut private_key.signatures;

        // Raise error, if array already contains a signature at index max_level - 1.
        if sig.get_mut(max_level - 1).is_some() {
            return Err(());
        }

        // Sign the message
        #[allow(unused_mut)]
        let mut signature_randomizer = generate_signature_randomizer::<H>(
            &SeedAndLmsTreeIdentifier {
                seed: prv[max_level - 1].seed.clone(),
                lms_tree_identifier: prv[max_level - 1].lms_tree_identifier,
            },
            &prv[max_level - 1].used_leafs_index,
        );
        let new_signature = if cfg!(feature = "fast_verify") && message_mut.is_some() {
            #[cfg(feature = "fast_verify")]
            let lms_sig = lms::signing::LmsSignature::sign_fast_verify(
                &mut prv[max_level - 1],
                None,
                message_mut,
                &mut signature_randomizer,
                aux_data,
            );
            #[cfg(not(feature = "fast_verify"))]
            let lms_sig = Err(());
            lms_sig
        } else {
            lms::signing::LmsSignature::sign(
                &mut prv[max_level - 1],
                message.unwrap(),
                &signature_randomizer,
                aux_data,
            )
        }?;
        sig.push(new_signature);

        // Create list of signed keys
        let mut signed_public_keys = ArrayVec::new();
        for i in 0..max_level - 1 {
            signed_public_keys.push(HssSignedPublicKey::new(sig[i].clone(), public[i].clone()));
        }

        Ok(HssSignature {
            level: max_level - 1,
            signed_public_keys,
            signature: sig[max_level - 1].clone(),
        })
    }

    pub fn to_binary_representation(&self) -> ArrayVec<[u8; MAX_HSS_SIGNATURE_LENGTH]> {
        let mut result = ArrayVec::new();

        result.extend_from_slice(&(self.level as u32).to_be_bytes());

        for signed_public_key in self.signed_public_keys.iter() {
            let binary_representation = signed_public_key.to_binary_representation();
            result.extend_from_slice(binary_representation.as_slice());
        }

        result.extend_from_slice(self.signature.to_binary_representation().as_slice());

        result
    }
}

/// To reduce memory footprint on verification we handle the signature in-memory using ```InMemoryHssSignature```.
/// In order to reduce complexity we use ```HssSignature``` for key generation and signature generation.
pub struct InMemoryHssSignature<'a, H: HashChain> {
    pub level: usize,
    pub signed_public_keys:
        ArrayVec<[Option<InMemoryHssSignedPublicKey<'a, H>>; MAX_ALLOWED_HSS_LEVELS - 1]>,
    pub signature: InMemoryLmsSignature<'a, H>,
}

impl<'a, H: HashChain> PartialEq<HssSignature<H>> for InMemoryHssSignature<'a, H> {
    fn eq(&self, other: &HssSignature<H>) -> bool {
        let first_condition = self.level == other.level && self.signature == other.signature;

        if !first_condition {
            return false;
        }

        for (x, y) in self
            .signed_public_keys
            .iter()
            .zip(other.signed_public_keys.iter())
        {
            if let Some(x) = x {
                if x != y {
                    return false;
                }
            } else {
                return false;
            }
        }

        true
    }
}

impl<'a, H: HashChain> InMemoryHssSignature<'a, H> {
    pub fn new(data: &'a [u8]) -> Option<Self> {
        let mut index = 0;

        let level =
            u32::from_be_bytes(read_and_advance(data, 4, &mut index).try_into().unwrap()) as usize;

        let mut signed_public_keys = ArrayVec::new();

        for _ in 0..level {
            let signed_public_key = InMemoryHssSignedPublicKey::<'a, H>::new(&data[index..])?;
            index += signed_public_key.len();
            signed_public_keys.push(Some(signed_public_key));
        }

        let signature = InMemoryLmsSignature::<'a, H>::new(&data[index..])?;

        Some(Self {
            level,
            signed_public_keys,
            signature,
        })
    }
}

#[derive(Default, Clone, PartialEq, Eq)]
pub struct HssSignedPublicKey<H: HashChain> {
    pub sig: LmsSignature<H>,
    pub public_key: LmsPublicKey<H>,
}

#[derive(Clone)]
pub struct InMemoryHssSignedPublicKey<'a, H: HashChain> {
    pub sig: InMemoryLmsSignature<'a, H>,
    pub public_key: InMemoryLmsPublicKey<'a, H>,
}

impl<'a, H: HashChain> PartialEq<HssSignedPublicKey<H>> for InMemoryHssSignedPublicKey<'a, H> {
    fn eq(&self, other: &HssSignedPublicKey<H>) -> bool {
        self.sig == other.sig && self.public_key == other.public_key
    }
}

impl<H: HashChain> HssSignedPublicKey<H> {
    pub fn new(signature: LmsSignature<H>, public_key: LmsPublicKey<H>) -> Self {
        Self {
            sig: signature,
            public_key,
        }
    }

    pub fn to_binary_representation(&self) -> ArrayVec<[u8; MAX_HSS_SIGNED_PUBLIC_KEY_LENGTH]> {
        let mut result = ArrayVec::new();

        result.extend_from_slice(self.sig.to_binary_representation().as_slice());
        result.extend_from_slice(self.public_key.to_binary_representation().as_slice());

        result
    }
}

impl<'a, H: HashChain> InMemoryHssSignedPublicKey<'a, H> {
    pub fn new(data: &'a [u8]) -> Option<Self> {
        let sig = InMemoryLmsSignature::new(data)?;

        let sig_size = lms_signature_length(
            sig.lmots_signature
                .lmots_parameter
                .get_hash_function_output_size(),
            sig.lmots_signature
                .lmots_parameter
                .get_num_winternitz_chains() as usize,
            sig.lms_parameter.get_tree_height() as usize,
        );

        let public_key = InMemoryLmsPublicKey::new(&data[sig_size..])?;

        Some(Self { sig, public_key })
    }

    pub fn len(&self) -> usize {
        let sig = &self.sig;
        let sig_size = lms_signature_length(
            sig.lmots_signature
                .lmots_parameter
                .get_hash_function_output_size(),
            sig.lmots_signature
                .lmots_parameter
                .get_num_winternitz_chains() as usize,
            sig.lms_parameter.get_tree_height() as usize,
        );
        let public_key_size =
            lms_public_key_length(sig.lms_parameter.get_hash_function_output_size());

        sig_size + public_key_size
    }
}

#[cfg(test)]
mod tests {
    use crate::{
        hasher::sha256::Sha256_256,
        hss::{
            reference_impl_private_key::ReferenceImplPrivateKey,
            signing::{
                InMemoryHssSignature, InMemoryHssSignedPublicKey, LmsSignature,
                SeedAndLmsTreeIdentifier,
            },
        },
        lms,
    };
    use crate::{HashChain, HssParameter};

    use super::{HssPrivateKey, HssSignature, HssSignedPublicKey};

    use crate::constants::LmsTreeIdentifier;
    use crate::util::helper::test_helper::gen_random_seed;
    use rand::{rngs::OsRng, RngCore};
    use tinyvec::ArrayVec;

    type Hasher = Sha256_256;

    #[test]
    #[should_panic(expected = "Signing should panic!")]
    fn reuse_loaded_keypair() {
        let seed = gen_random_seed::<Hasher>();
        let private_key = ReferenceImplPrivateKey::<Hasher>::generate(
            &[
                HssParameter::construct_default_parameters(),
                HssParameter::construct_default_parameters(),
            ],
            &seed,
        )
        .unwrap();

        let mut private_key = HssPrivateKey::from(&private_key, &mut None).unwrap();

        let message = [2, 56, 123, 22, 42, 49, 22];

        let _ = HssSignature::sign(&mut private_key, Some(&message), None, &mut None)
            .expect("Should generate HSS signature");

        let _ = HssSignature::sign(&mut private_key, Some(&message), None, &mut None)
            .expect("Signing should panic!");
    }

    #[test]
    fn test_signed_public_key_binary_representation() {
        let seed_and_lms_tree_identifier = SeedAndLmsTreeIdentifier {
            seed: gen_random_seed::<Hasher>(),
            lms_tree_identifier: LmsTreeIdentifier::default(),
        };
        let mut keypair = lms::generate_key_pair::<Hasher>(
            &seed_and_lms_tree_identifier,
            &HssParameter::construct_default_parameters(),
            &0,
            &mut None,
        );

        let message = [3, 54, 32, 45, 67, 32, 12, 58, 29, 49];
        let mut signature_randomizer =
            ArrayVec::from_array_len([0u8; 32], Hasher::OUTPUT_SIZE as usize);
        OsRng.fill_bytes(&mut signature_randomizer);
        let signature = LmsSignature::sign(
            &mut keypair.private_key,
            &message,
            &signature_randomizer,
            &mut None,
        )
        .expect("Signing should work");

        let signed_public_key = HssSignedPublicKey {
            public_key: keypair.public_key,
            sig: signature,
        };

        let binary_representation = signed_public_key.to_binary_representation();
        let deserialized = InMemoryHssSignedPublicKey::new(binary_representation.as_slice())
            .expect("Deserialization should work.");

        assert!(deserialized == signed_public_key);
    }

    #[test]
    fn test_hss_signature_binary_representation() {
        let seed = gen_random_seed::<Hasher>();
        let private_key = ReferenceImplPrivateKey::<Hasher>::generate(
            &[
                HssParameter::construct_default_parameters(),
                HssParameter::construct_default_parameters(),
            ],
            &seed,
        )
        .unwrap();

        let mut private_key = HssPrivateKey::from(&private_key, &mut None).unwrap();

        let message_values = [2, 56, 123, 22, 42, 49, 22];
        let mut message = [0u8; 64];
        message[..message_values.len()].copy_from_slice(&message_values);

        let signature = HssSignature::sign(&mut private_key, Some(&message), None, &mut None)
            .expect("Should generate HSS signature");

        let binary_representation = signature.to_binary_representation();
        let deserialized = InMemoryHssSignature::<Hasher>::new(binary_representation.as_slice())
            .expect("Deserialization should work.");

        assert!(deserialized == signature);
    }
}
