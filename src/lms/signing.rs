use crate::constants::LmsLeafIdentifier;
use crate::constants::MAX_HASH_SIZE;
use crate::constants::MAX_LMS_SIGNATURE_LENGTH;
use crate::extract_or_return;
use crate::hasher::Hasher;
use crate::lm_ots;
use crate::lm_ots::definitions::LmotsPrivateKey;
use crate::lm_ots::parameters::LmotsAlgorithm;
use crate::lm_ots::signing::InMemoryLmotsSignature;
use crate::lm_ots::signing::LmotsSignature;
use crate::lms::definitions::LmsPrivateKey;
use crate::lms::parameters::LmsAlgorithm;
use crate::util::ustr::str32u;
use crate::util::ustr::u32str;
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

impl<H: 'static + Hasher> LmsSignature<H> {
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
    ) -> Result<LmsSignature<H>, ()> {
        let lm_ots_private_key = lms_private_key.use_lmots_private_key()?;

        let ots_signature =
            LmotsSignature::sign_fast_verify(&lm_ots_private_key, message, message_mut);

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
    ) -> Result<LmsSignature<H>, ()> {
        let lm_ots_private_key = lms_private_key.use_lmots_private_key()?;

        let ots_signature = LmotsSignature::sign(&lm_ots_private_key, message);

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

        if data.len() < 8 {
            return None;
        }

        let mut consumed_data = data;

        let lms_leaf_identifier = str32u(&consumed_data[..4]);
        consumed_data = &consumed_data[4..];

        let lm_ots_type = str32u(&consumed_data[..4]);
        // consumed_data = &consumed_data[4..];

        let lmots_parameter = extract_or_return!(LmotsAlgorithm::get_from_type::<H>(lm_ots_type));

        let lmots_hash_output_size = lmots_parameter.get_hash_function_output_size();
        let max_hash_iterations = lmots_parameter.get_max_hash_iterations();

        if data.len() < 12 + lmots_hash_output_size as usize * (max_hash_iterations as usize + 1) {
            return None;
        }

        let lmots_signature = match lm_ots::signing::InMemoryLmotsSignature::new(
            &data[4..=(7 + lmots_hash_output_size as usize * (max_hash_iterations as usize + 1))],
        ) {
            None => return None,
            Some(x) => x,
        };

        let lms_type_start =
            8 + lmots_hash_output_size as usize * (max_hash_iterations as usize + 1);
        let lms_type_end =
            11 + lmots_hash_output_size as usize * (max_hash_iterations as usize + 1);

        let lms_type = str32u(&data[lms_type_start..=lms_type_end]);

        let lms_parameter = extract_or_return!(LmsAlgorithm::get_from_type(lms_type));

        let tree_height = lms_parameter.get_tree_height();

        if lms_leaf_identifier >= 2u32.pow(tree_height as u32) {
            return None;
        }

        let lms_hash_output_size = lms_parameter.get_hash_function_output_size();

        if data.len()
            < 12 + lmots_hash_output_size as usize * (max_hash_iterations as usize + 1)
                + lms_hash_output_size as usize * tree_height as usize
        {
            return None;
        }

        let mut tree_slice = data;
        let tree_start = 12
            + lmots_parameter.get_hash_function_output_size() as usize
                * (lmots_parameter.get_max_hash_iterations() as usize + 1);

        tree_slice = &tree_slice[tree_start..];

        let trees: &[u8] =
            &tree_slice[..lms_parameter.get_hash_function_output_size() * tree_height as usize];

        let signature = Self {
            lms_parameter,
            lms_leaf_identifier,
            lmots_signature,
            authentication_path: trees,
        };

        Some(signature)
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
            LmsSignature::sign(&mut private_key, message).expect("Signing must succeed.");

        let binary = signature.to_binary_representation();

        let deserialized =
            InMemoryLmsSignature::new(binary.as_slice()).expect("Deserialization must succeed.");

        assert!(deserialized == signature);
    }
}
