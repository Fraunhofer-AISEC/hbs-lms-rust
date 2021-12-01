use crate::constants::*;
use crate::extract_or_return;
use crate::hasher::Hasher;
use crate::lm_ots;
use crate::lm_ots::definitions::LmotsPrivateKey;
use crate::lm_ots::parameters::LmotsAlgorithm;
use crate::lm_ots::parameters::LmotsParameter;
use crate::lms::parameters::LmsAlgorithm;
use crate::util::helper::read_and_advance;
use crate::util::ustr::str32u;
use crate::util::ustr::u32str;
use arrayvec::ArrayVec;

use super::parameters::LmsParameter;

#[derive(Debug, Default, Clone, Copy, PartialEq)]
pub struct LmsPrivateKey<H: Hasher> {
    pub lms_tree_identifier: LmsTreeIdentifier,
    pub used_leafs_index: u32,
    pub seed: Seed,
    pub lmots_parameter: LmotsParameter<H>,
    pub lms_parameter: LmsParameter<H>,
}

impl<H: Hasher> LmsPrivateKey<H> {
    pub fn new(
        seed: Seed,
        lms_tree_identifier: LmsTreeIdentifier,
        used_leafs_index: u32,
        lmots_parameter: LmotsParameter<H>,
        lms_parameter: LmsParameter<H>,
    ) -> Self {
        LmsPrivateKey {
            seed,
            lms_tree_identifier,
            used_leafs_index,
            lmots_parameter,
            lms_parameter,
        }
    }

    pub fn use_lmots_private_key(&mut self) -> Result<LmotsPrivateKey<H>, ()> {
        let number_of_lm_ots_keys = self.lms_parameter.number_of_lm_ots_keys();

        if self.used_leafs_index as usize >= number_of_lm_ots_keys {
            return Err(());
        }

        let key = lm_ots::generate_private_key(
            self.lms_tree_identifier,
            u32str(self.used_leafs_index),
            self.seed,
            self.lmots_parameter,
        );
        self.used_leafs_index += 1;

        Ok(key)
    }
}

#[derive(Debug, Clone, Default, PartialEq)]
pub struct LmsPublicKey<H: Hasher> {
    pub key: ArrayVec<u8, MAX_HASH_SIZE>,
    pub lms_tree_identifier: LmsTreeIdentifier,
    pub lmots_parameter: LmotsParameter<H>,
    pub lms_parameter: LmsParameter<H>,
}

#[derive(Clone)]
pub struct InMemoryLmsPublicKey<'a, H: Hasher> {
    pub key: &'a [u8],
    pub lms_tree_identifier: &'a [u8],
    pub lmots_parameter: LmotsParameter<H>,
    pub lms_parameter: LmsParameter<H>,
    complete_data: &'a [u8],
}

impl<'a, H: Hasher> PartialEq<LmsPublicKey<H>> for InMemoryLmsPublicKey<'a, H> {
    fn eq(&self, other: &LmsPublicKey<H>) -> bool {
        self.key == other.key.as_slice()
            && self.lms_tree_identifier == &other.lms_tree_identifier[..]
            && self.lmots_parameter == other.lmots_parameter
            && self.lms_parameter == other.lms_parameter
            && self.complete_data == other.to_binary_representation().as_slice()
    }
}

impl<H: Hasher> LmsPublicKey<H> {
    pub fn new(
        public_key: ArrayVec<u8, MAX_HASH_SIZE>,
        lms_tree_identifier: LmsTreeIdentifier,
        lmots_parameter: LmotsParameter<H>,
        lms_parameter: LmsParameter<H>,
    ) -> Self {
        LmsPublicKey {
            key: public_key,
            lms_tree_identifier,
            lmots_parameter,
            lms_parameter,
        }
    }

    pub fn to_binary_representation(&self) -> ArrayVec<u8, MAX_LMS_PUBLIC_KEY_LENGTH> {
        let mut result = ArrayVec::new();

        result
            .try_extend_from_slice(&u32str(self.lms_parameter.get_type_id()))
            .unwrap();
        result
            .try_extend_from_slice(&u32str(self.lmots_parameter.get_type_id()))
            .unwrap();

        result
            .try_extend_from_slice(&self.lms_tree_identifier)
            .unwrap();

        result.try_extend_from_slice(self.key.as_slice()).unwrap();

        result
    }
}

impl<'a, H: Hasher> InMemoryLmsPublicKey<'a, H> {
    pub fn new(data: &'a [u8]) -> Option<Self> {
        // Parsing like desribed in 5.4.2
        if data.len() < 8 {
            return None;
        }

        let mut data_index = 0;

        let lms_type = str32u(read_and_advance(data, 4, &mut data_index));

        let lms_parameter = extract_or_return!(LmsAlgorithm::get_from_type(lms_type));

        let lm_ots_typecode = str32u(read_and_advance(data, 4, &mut data_index));

        let lmots_parameter = extract_or_return!(LmotsAlgorithm::get_from_type(lm_ots_typecode));

        if data.len() - data_index == 24 + lms_parameter.get_hash_function_output_size() as usize {
            return None;
        }

        let lms_tree_identifier: &'a [u8] = &data[data_index..data_index + 16];
        data_index += 16;

        let key: &'a [u8] =
            &data[data_index..data_index + lms_parameter.get_hash_function_output_size() as usize];

        let public_key = Self {
            lmots_parameter,
            lms_parameter,
            lms_tree_identifier,
            key,
            complete_data: &data
                [..data_index + lms_parameter.get_hash_function_output_size() as usize],
        };

        Some(public_key)
    }

    pub fn as_slice(&self) -> &[u8] {
        self.complete_data
    }
}

#[cfg(test)]
mod tests {
    use crate::{
        hasher::sha256::Sha256Hasher,
        lm_ots::parameters::LmotsAlgorithm,
        lms::{
            definitions::InMemoryLmsPublicKey,
            keygen::{generate_private_key, generate_public_key},
            parameters::LmsAlgorithm,
        },
    };

    #[test]
    fn test_public_key_binary_representation() {
        let private_key = generate_private_key::<Sha256Hasher>(
            LmotsAlgorithm::construct_default_parameter(),
            LmsAlgorithm::construct_default_parameter(),
        );

        let public_key = generate_public_key(&private_key, &mut None);

        let serialized = public_key.to_binary_representation();
        let deserialized = InMemoryLmsPublicKey::new(serialized.as_slice())
            .expect("Deserialization must succeed.");

        assert!(deserialized == public_key);
    }
}
