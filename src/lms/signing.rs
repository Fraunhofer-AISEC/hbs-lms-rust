use crate::constants::LmsLeafIdentifier;
use crate::constants::MAX_HASH_SIZE;
use crate::constants::MAX_LMS_SIGNATURE_LENGTH;
use crate::hasher::Hasher;
use crate::lm_ots;
use crate::lm_ots::definitions::LmotsPrivateKey;
use crate::lm_ots::parameters::LmotsAlgorithm;
use crate::lm_ots::signing::InMemoryLmotsSignature;
use crate::lm_ots::signing::LmotsSignature;
use crate::lms::definitions::LmsPrivateKey;
use crate::lms::parameters::LmsAlgorithm;
use crate::util::{
    helper::{read, read_and_advance},
    ustr::{str32u, u32str},
};
use arrayvec::ArrayVec;

use super::helper::get_tree_element;
use super::parameters::LmsParameter;

#[derive(Debug, Default, Clone, PartialEq)]
pub struct LmsSignature<H: Hasher> {
    pub lms_leaf_identifier: LmsLeafIdentifier,
    pub lmots_signature: LmotsSignature<H>,
    pub authentication_path: ArrayVec<ArrayVec<u8, MAX_HASH_SIZE>, MAX_HASH_SIZE>,
    pub lms_parameter: LmsParameter<H>,
}

#[derive(Clone)]
pub struct InMemoryLmsSignature<'a, H: Hasher> {
    pub lms_leaf_identifier: u32,
    pub lmots_signature: InMemoryLmotsSignature<'a, H>,
    pub authentication_path: &'a [u8],
    pub lms_parameter: LmsParameter<H>,
}

impl<'a, H: Hasher> PartialEq<LmsSignature<H>> for InMemoryLmsSignature<'a, H> {
    fn eq(&self, other: &LmsSignature<H>) -> bool {
        let first_condition = self.lms_leaf_identifier == str32u(&other.lms_leaf_identifier[..])
            && self.lmots_signature == other.lmots_signature
            && self.lms_parameter == other.lms_parameter;

        if !first_condition {
            return false;
        }

        let mut curr = self.authentication_path;

        for hash_chain_value in other.authentication_path.iter() {
            for hash_chain_byte in hash_chain_value.iter() {
                if curr[0] != *hash_chain_byte {
                    return false;
                }
                curr = &curr[1..];
            }
        }

        true
    }
}

impl<H: Hasher> LmsSignature<H> {
    fn build_authentication_path(
        lms_private_key: &mut LmsPrivateKey<H>,
        lm_ots_private_key: &LmotsPrivateKey<H>,
    ) -> Result<ArrayVec<ArrayVec<u8, MAX_HASH_SIZE>, MAX_HASH_SIZE>, ()> {
        let tree_height = lms_private_key.lms_parameter.get_tree_height();
        let signature_leaf_index = 2usize.pow(tree_height as u32)
            + str32u(&lm_ots_private_key.lms_leaf_identifier) as usize;

        let mut authentication_path = ArrayVec::new();

        for i in 0..tree_height.into() {
            let tree_index = (signature_leaf_index / (2usize.pow(i as u32))) ^ 0x1;
            authentication_path.push(get_tree_element(tree_index, lms_private_key, &mut None));
        }

        Ok(authentication_path)
    }

    pub fn sign_fast_verify(
        lms_private_key: &mut LmsPrivateKey<H>,
        message: Option<&[u8]>,
        message_mut: Option<&mut [u8]>,
        signature_randomizer: Option<ArrayVec<u8, MAX_HASH_SIZE>>,
    ) -> Result<LmsSignature<H>, ()> {
        let lm_ots_private_key = lms_private_key.use_lmots_private_key()?;

        let ots_signature = LmotsSignature::sign_fast_verify(
            &lm_ots_private_key,
            signature_randomizer,
            message,
            message_mut,
        );

        let authentication_path =
            LmsSignature::<H>::build_authentication_path(lms_private_key, &lm_ots_private_key)?;

        let signature = LmsSignature {
            lms_leaf_identifier: lm_ots_private_key.lms_leaf_identifier,
            lmots_signature: ots_signature,
            authentication_path,
            lms_parameter: lms_private_key.lms_parameter,
        };

        Ok(signature)
    }

    pub fn sign(
        lms_private_key: &mut LmsPrivateKey<H>,
        message: &[u8],
        signature_randomizer: Option<ArrayVec<u8, MAX_HASH_SIZE>>,
    ) -> Result<LmsSignature<H>, ()> {
        let lm_ots_private_key = lms_private_key.use_lmots_private_key()?;

        let ots_signature =
            LmotsSignature::sign(&lm_ots_private_key, signature_randomizer, message);

        let authentication_path =
            LmsSignature::<H>::build_authentication_path(lms_private_key, &lm_ots_private_key)?;

        let signature = LmsSignature {
            lms_leaf_identifier: lm_ots_private_key.lms_leaf_identifier,
            lmots_signature: ots_signature,
            authentication_path,
            lms_parameter: lms_private_key.lms_parameter,
        };

        Ok(signature)
    }

    pub fn to_binary_representation(&self) -> ArrayVec<u8, MAX_LMS_SIGNATURE_LENGTH> {
        let mut result = ArrayVec::new();

        result
            .try_extend_from_slice(&self.lms_leaf_identifier)
            .unwrap();

        let lmots_signature = self.lmots_signature.to_binary_representation();

        result
            .try_extend_from_slice(lmots_signature.as_slice())
            .unwrap();

        result
            .try_extend_from_slice(&u32str(self.lms_parameter.get_type_id() as u32))
            .unwrap();

        for element in self.authentication_path.iter() {
            result.try_extend_from_slice(element.as_slice()).unwrap();
        }

        result
    }
}

impl<'a, H: Hasher> InMemoryLmsSignature<'a, H> {
    pub fn new(data: &'a [u8]) -> Option<Self> {
        // Parsing like 5.4.2 Algorithm 6a
        let mut index = 0;

        let lms_leaf_identifier = str32u(read_and_advance(data, 4, &mut index));

        // LMOTS Signature consists of LMOTS parameter, signature randomizer & signature data
        let lmots_parameter =
            LmotsAlgorithm::get_from_type::<H>(str32u(read(data, 4, &index))).unwrap();
        let lmots_signature = lm_ots::signing::InMemoryLmotsSignature::new(read_and_advance(
            data,
            (4 + H::OUTPUT_SIZE * (1 + lmots_parameter.get_max_hash_iterations())) as usize,
            &mut index,
        ))
        .unwrap();

        let lms_parameter =
            LmsAlgorithm::get_from_type(str32u(read_and_advance(data, 4, &mut index))).unwrap();
        let authentication_path = read_and_advance(
            data,
            (H::OUTPUT_SIZE * lms_parameter.get_tree_height() as u16) as usize,
            &mut index,
        );

        if lms_leaf_identifier >= lms_parameter.number_of_lm_ots_keys() as u32 {
            return None;
        }

        Some(Self {
            lms_parameter,
            lms_leaf_identifier,
            lmots_signature,
            authentication_path,
        })
    }

    pub fn get_path(&self, index: usize) -> &[u8] {
        let step = self.lms_parameter.get_hash_function_output_size();
        let start = step * index;
        let end = start + step;
        &self.authentication_path[start..end]
    }
}

#[cfg(test)]
mod tests {
    use crate::{
        lm_ots::parameters::LmotsAlgorithm,
        lms::{
            keygen::generate_private_key, parameters::LmsAlgorithm, signing::InMemoryLmsSignature,
        },
    };

    use super::LmsSignature;

    #[test]
    fn test_binary_representation_of_signature() {
        let mut private_key = generate_private_key(
            LmotsAlgorithm::construct_default_parameter(),
            LmsAlgorithm::construct_default_parameter(),
        );

        let message = "Hi, what up?".as_bytes();

        let signature =
            LmsSignature::sign(&mut private_key, message, None).expect("Signing must succeed.");

        let binary = signature.to_binary_representation();

        let deserialized =
            InMemoryLmsSignature::new(binary.as_slice()).expect("Deserialization must succeed.");

        assert!(deserialized == signature);
    }
}
