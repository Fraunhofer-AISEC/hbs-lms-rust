use crate::constants::*;
use crate::hasher::HashChain;
use crate::lm_ots::definitions::LmotsPrivateKey;
use crate::lm_ots::parameters::{LmotsAlgorithm, LmotsParameter};
use crate::lms::helper::get_tree_element;
use crate::lms::parameters::LmsAlgorithm;
use crate::lms::MutableExpandedAuxData;
use crate::sst::helper::get_sst_last_leaf_idx;
use crate::sst::parameters::SstExtension;
use crate::util::helper::read_and_advance;
use crate::{lm_ots, Seed};

use core::convert::TryInto;
use tinyvec::ArrayVec;
use zeroize::{Zeroize, ZeroizeOnDrop};

use super::parameters::LmsParameter;

#[derive(Debug, Default, Clone, PartialEq, Eq, Zeroize, ZeroizeOnDrop)]
pub struct LmsPrivateKey<H: HashChain> {
    pub lms_tree_identifier: LmsTreeIdentifier,
    pub used_leafs_index: u32,
    pub seed: Seed<H>,
    #[zeroize(skip)]
    pub lmots_parameter: LmotsParameter<H>,
    #[zeroize(skip)]
    pub lms_parameter: LmsParameter<H>,
    pub sst_ext: Option<SstExtension>,
}

impl<H: HashChain> LmsPrivateKey<H> {
    pub fn new(
        seed: Seed<H>,
        lms_tree_identifier: LmsTreeIdentifier,
        used_leafs_index: u32,
        lmots_parameter: LmotsParameter<H>,
        lms_parameter: LmsParameter<H>,
        sst_ext: Option<SstExtension>,
    ) -> Self {
        LmsPrivateKey {
            seed,
            lms_tree_identifier,
            used_leafs_index,
            lmots_parameter,
            lms_parameter,
            sst_ext,
        }
    }

    pub fn use_lmots_private_key(&mut self) -> Result<LmotsPrivateKey<H>, ()> {
        let number_of_lm_ots_keys = {
            if let Some(my_sst_ext) = &self.sst_ext {
                // our last leafs function returns 0..total_num-1, but here we need 1..total_num
                1 + get_sst_last_leaf_idx(
                    my_sst_ext.signing_entity_idx,
                    self.lms_parameter.get_tree_height(),
                    my_sst_ext.top_div_height,
                )
            } else {
                self.lms_parameter.number_of_lm_ots_keys() as u32
            }
        };

        if self.used_leafs_index >= number_of_lm_ots_keys {
            return Err(());
        }

        let key = lm_ots::keygen::generate_private_key(
            self.lms_tree_identifier,
            self.used_leafs_index.to_be_bytes(),
            self.seed.clone(),
            self.lmots_parameter,
        );
        self.used_leafs_index += 1;

        Ok(key)
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct LmsPublicKey<H: HashChain> {
    pub key: Node,
    pub lms_tree_identifier: LmsTreeIdentifier,
    pub lmots_parameter: LmotsParameter<H>,
    pub lms_parameter: LmsParameter<H>,
}

impl<H: HashChain> LmsPublicKey<H> {
    pub fn new(
        private_key: &LmsPrivateKey<H>,
        aux_data: &mut Option<MutableExpandedAuxData>,
    ) -> Self {
        let public_key = get_tree_element(1_usize, private_key, aux_data);

        Self {
            key: public_key,
            lms_tree_identifier: private_key.lms_tree_identifier,
            lmots_parameter: private_key.lmots_parameter,
            lms_parameter: private_key.lms_parameter,
        }
    }

    pub fn to_binary_representation(&self) -> ArrayVec<[u8; MAX_LMS_PUBLIC_KEY_LENGTH]> {
        let mut result = ArrayVec::new();

        result.extend_from_slice(&self.lms_parameter.get_type_id().to_be_bytes());
        result.extend_from_slice(&self.lmots_parameter.get_type_id().to_be_bytes());

        result.extend_from_slice(&self.lms_tree_identifier);

        result.extend_from_slice(self.key.as_slice());

        result
    }
}

#[derive(Clone)]
pub struct InMemoryLmsPublicKey<'a, H: HashChain> {
    pub key: &'a [u8],
    pub lms_tree_identifier: &'a [u8],
    pub lmots_parameter: LmotsParameter<H>,
    pub lms_parameter: LmsParameter<H>,
    complete_data: &'a [u8],
}

impl<'a, H: HashChain> PartialEq<LmsPublicKey<H>> for InMemoryLmsPublicKey<'a, H> {
    fn eq(&self, other: &LmsPublicKey<H>) -> bool {
        self.key == other.key.as_slice()
            && self.lms_tree_identifier == &other.lms_tree_identifier[..]
            && self.lmots_parameter == other.lmots_parameter
            && self.lms_parameter == other.lms_parameter
            && self.complete_data == other.to_binary_representation().as_slice()
    }
}

impl<'a, H: HashChain> InMemoryLmsPublicKey<'a, H> {
    pub fn new(data: &'a [u8]) -> Option<Self> {
        // Parsing like described in 5.4.2
        let mut data_index = 0;

        let lms_parameter = LmsAlgorithm::get_from_type(u32::from_be_bytes(
            read_and_advance(data, 4, &mut data_index)
                .try_into()
                .unwrap(),
        ))?;
        let lmots_parameter = LmotsAlgorithm::get_from_type(u32::from_be_bytes(
            read_and_advance(data, 4, &mut data_index)
                .try_into()
                .unwrap(),
        ))?;
        let lms_tree_identifier = read_and_advance(data, 16, &mut data_index);
        let key = read_and_advance(data, H::OUTPUT_SIZE.into(), &mut data_index);

        Some(Self {
            lmots_parameter,
            lms_parameter,
            lms_tree_identifier,
            key,
            complete_data: &data[..data_index],
        })
    }

    pub fn as_slice(&self) -> &[u8] {
        self.complete_data
    }
}

#[cfg(test)]
mod tests {
    use crate::{
        lm_ots::parameters::LmotsAlgorithm,
        lms::{
            definitions::{InMemoryLmsPublicKey, LmsPrivateKey, LmsPublicKey},
            parameters::LmsAlgorithm,
            SeedAndLmsTreeIdentifier,
        },
    };

    use rand::{rngs::OsRng, RngCore};

    #[test]
    fn test_public_key_binary_representation() {
        let mut seed_and_lms_tree_identifier = SeedAndLmsTreeIdentifier::default();
        OsRng.fill_bytes(seed_and_lms_tree_identifier.seed.as_mut_slice());
        let private_key = LmsPrivateKey::new(
            seed_and_lms_tree_identifier.seed.clone(),
            seed_and_lms_tree_identifier.lms_tree_identifier,
            0,
            LmotsAlgorithm::construct_default_parameter(),
            LmsAlgorithm::construct_default_parameter(),
            None,
        );

        let public_key = LmsPublicKey::new(&private_key, &mut None);

        let serialized = public_key.to_binary_representation();
        let deserialized = InMemoryLmsPublicKey::new(serialized.as_slice())
            .expect("Deserialization must succeed.");

        assert!(deserialized == public_key);
    }
}
