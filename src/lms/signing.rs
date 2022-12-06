use crate::constants::{
    LmsLeafIdentifier, MAX_HASH_SIZE, MAX_LMS_SIGNATURE_LENGTH, MAX_TREE_HEIGHT,
};
use crate::hasher::HashChain;
use crate::hss::aux::MutableExpandedAuxData;
use crate::lm_ots;
use crate::lm_ots::definitions::LmotsPrivateKey;
use crate::lm_ots::parameters::LmotsAlgorithm;
use crate::lm_ots::signing::InMemoryLmotsSignature;
use crate::lm_ots::signing::LmotsSignature;
use crate::lms::definitions::LmsPrivateKey;
use crate::lms::parameters::LmsAlgorithm;
use crate::util::helper::{read, read_and_advance};

use core::convert::TryInto;
use tinyvec::ArrayVec;

use super::helper::get_tree_element;
use super::parameters::LmsParameter;

#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct LmsSignature<H: HashChain> {
    pub lms_leaf_identifier: LmsLeafIdentifier,
    pub lmots_signature: LmotsSignature<H>,
    pub authentication_path: ArrayVec<[ArrayVec<[u8; MAX_HASH_SIZE]>; MAX_TREE_HEIGHT]>,
    pub lms_parameter: LmsParameter<H>,
}

#[derive(Clone)]
pub struct InMemoryLmsSignature<'a, H: HashChain> {
    pub lms_leaf_identifier: u32,
    pub lmots_signature: InMemoryLmotsSignature<'a, H>,
    pub authentication_path: &'a [u8],
    pub lms_parameter: LmsParameter<H>,
}

impl<'a, H: HashChain> PartialEq<LmsSignature<H>> for InMemoryLmsSignature<'a, H> {
    fn eq(&self, other: &LmsSignature<H>) -> bool {
        let first_condition = self.lms_leaf_identifier
            == u32::from_be_bytes(other.lms_leaf_identifier)
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

impl<H: HashChain> LmsSignature<H> {
    fn build_authentication_path(
        lms_private_key: &mut LmsPrivateKey<H>,
        lm_ots_private_key: &LmotsPrivateKey<H>,
        aux_data: &mut Option<MutableExpandedAuxData>,
    ) -> Result<ArrayVec<[ArrayVec<[u8; MAX_HASH_SIZE]>; MAX_TREE_HEIGHT]>, ()> {
        let tree_height = lms_private_key.lms_parameter.get_tree_height();
        let signature_leaf_index = 2usize.pow(tree_height as u32)
            + u32::from_be_bytes(lm_ots_private_key.lms_leaf_identifier) as usize;

        let mut authentication_path = ArrayVec::new();

        for i in 0..tree_height.into() {
            let tree_index = (signature_leaf_index / (2usize.pow(i as u32))) ^ 0x1;
            authentication_path.push(get_tree_element(tree_index, lms_private_key, aux_data));
        }

        Ok(authentication_path)
    }

    #[cfg(feature = "fast_verify")]
    pub fn sign_fast_verify(
        lms_private_key: &mut LmsPrivateKey<H>,
        message: Option<&[u8]>,
        message_mut: Option<&mut [u8]>,
        signature_randomizer: &mut ArrayVec<[u8; MAX_HASH_SIZE]>,
        aux_data: &mut Option<MutableExpandedAuxData>,
    ) -> Result<LmsSignature<H>, ()> {
        let lm_ots_private_key = lms_private_key.use_lmots_private_key()?;

        let ots_signature = LmotsSignature::sign_fast_verify(
            &lm_ots_private_key,
            signature_randomizer,
            message,
            message_mut,
        );

        let authentication_path = LmsSignature::<H>::build_authentication_path(
            lms_private_key,
            &lm_ots_private_key,
            aux_data,
        )?;

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
        signature_randomizer: &ArrayVec<[u8; MAX_HASH_SIZE]>,
        aux_data: &mut Option<MutableExpandedAuxData>,
    ) -> Result<LmsSignature<H>, ()> {
        let lm_ots_private_key = lms_private_key.use_lmots_private_key()?;

        let ots_signature =
            LmotsSignature::sign(&lm_ots_private_key, signature_randomizer, message);

        let authentication_path = LmsSignature::<H>::build_authentication_path(
            lms_private_key,
            &lm_ots_private_key,
            aux_data,
        )?;

        let signature = LmsSignature {
            lms_leaf_identifier: lm_ots_private_key.lms_leaf_identifier,
            lmots_signature: ots_signature,
            authentication_path,
            lms_parameter: lms_private_key.lms_parameter,
        };

        Ok(signature)
    }

    pub fn to_binary_representation(&self) -> ArrayVec<[u8; MAX_LMS_SIGNATURE_LENGTH]> {
        let mut result = ArrayVec::new();

        result.extend_from_slice(&self.lms_leaf_identifier);

        let lmots_signature = self.lmots_signature.to_binary_representation();

        result.extend_from_slice(lmots_signature.as_slice());

        result.extend_from_slice(&self.lms_parameter.get_type_id().to_be_bytes());

        for element in self.authentication_path.iter() {
            result.extend_from_slice(element.as_slice());
        }

        result
    }
}

impl<'a, H: HashChain> InMemoryLmsSignature<'a, H> {
    pub fn new(data: &'a [u8]) -> Option<Self> {
        // Parsing like 5.4.2 Algorithm 6a
        let mut index = 0;

        let lms_leaf_identifier =
            u32::from_be_bytes(read_and_advance(data, 4, &mut index).try_into().unwrap());

        // LMOTS Signature consists of LMOTS parameter, signature randomizer & signature data
        let lmots_parameter = LmotsAlgorithm::get_from_type::<H>(u32::from_be_bytes(
            read(data, 4, &index).try_into().unwrap(),
        ))
        .unwrap();
        let lmots_signature = lm_ots::signing::InMemoryLmotsSignature::new(read_and_advance(
            data,
            (4 + H::OUTPUT_SIZE * (1 + lmots_parameter.get_hash_chain_count())) as usize,
            &mut index,
        ))
        .unwrap();

        let _type = u32::from_be_bytes(read_and_advance(data, 4, &mut index).try_into().unwrap());

        let lms_parameter = LmsAlgorithm::get_from_type(_type).unwrap();
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
            definitions::LmsPrivateKey, parameters::LmsAlgorithm, signing::InMemoryLmsSignature,
            SeedAndLmsTreeIdentifier,
        },
    };

    use super::LmsSignature;

    use rand::{rngs::OsRng, RngCore};
    use tinyvec::ArrayVec;

    #[test]
    fn test_binary_representation_of_signature() {
        let mut seed_and_lms_tree_identifier = SeedAndLmsTreeIdentifier::default();
        OsRng.fill_bytes(seed_and_lms_tree_identifier.seed.as_mut_slice());
        let mut private_key = LmsPrivateKey::new(
            seed_and_lms_tree_identifier.seed,
            seed_and_lms_tree_identifier.lms_tree_identifier,
            0,
            LmotsAlgorithm::construct_default_parameter(),
            LmsAlgorithm::construct_default_parameter(),
        );

        let message = "Hi, what up?".as_bytes();
        let mut signature_randomizer = ArrayVec::from([0u8; 32]);
        OsRng.fill_bytes(&mut signature_randomizer);

        let signature =
            LmsSignature::sign(&mut private_key, message, &signature_randomizer, &mut None)
                .expect("Signing must succeed.");

        let binary = signature.to_binary_representation();

        let deserialized =
            InMemoryLmsSignature::new(binary.as_slice()).expect("Deserialization must succeed.");

        assert!(deserialized == signature);
    }
}
