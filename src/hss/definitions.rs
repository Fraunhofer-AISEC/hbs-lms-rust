use arrayvec::ArrayVec;
use core::convert::TryFrom;

use crate::{
    constants::{MAX_ALLOWED_HSS_LEVELS, MAX_LMS_PUBLIC_KEY_LENGTH},
    hasher::Hasher,
    hss::aux::{
        hss_expand_aux_data, hss_finalize_aux_data, hss_optimal_aux_level, hss_store_aux_marker,
    },
    lms::{
        definitions::InMemoryLmsPublicKey, generate_key_pair_with_seed_and_aux,
        parameters::LmsParameter,
    },
    util::{
        helper::read_and_advance,
        ustr::{str32u, u32str},
    },
};
use crate::{
    hss::aux::hss_get_aux_data_len,
    lms::{
        self,
        definitions::{LmsPrivateKey, LmsPublicKey},
        signing::LmsSignature,
    },
};

use super::reference_impl_private_key::ReferenceImplPrivateKey;
use super::{
    aux::{hss_is_aux_data_used, MutableExpandedAuxData},
    reference_impl_private_key::{
        generate_child_seed_and_lms_tree_identifier, generate_child_signature_randomizer,
    },
};

#[derive(Debug, Default, PartialEq)]
pub struct HssPrivateKey<H: Hasher> {
    pub private_key: ArrayVec<LmsPrivateKey<H>, MAX_ALLOWED_HSS_LEVELS>,
    pub public_key: ArrayVec<LmsPublicKey<H>, MAX_ALLOWED_HSS_LEVELS>,
    pub signatures: ArrayVec<LmsSignature<H>, { MAX_ALLOWED_HSS_LEVELS - 1 }>, // Only L - 1 signatures needed
}

impl<H: 'static + Hasher> HssPrivateKey<H> {
    pub fn get_length(&self) -> usize {
        self.private_key.len()
    }

    pub fn from(
        private_key: &ReferenceImplPrivateKey<H>,
        aux_data: Option<&mut &mut [u8]>,
    ) -> Result<Self, ()> {
        let parameters = private_key.compressed_parameter.to::<H>()?;
        let levels = parameters.len();
        let used_leafs_indexes = private_key.compressed_used_leafs_indexes.to(&parameters);

        let top_lms_parameter = parameters[0].get_lms_parameter();

        let is_aux_data_used = if let Some(ref aux_data) = aux_data {
            hss_is_aux_data_used(aux_data)
        } else {
            false
        };

        let mut expanded_aux_data = HssPrivateKey::get_expanded_aux_data(
            aux_data,
            private_key,
            top_lms_parameter,
            is_aux_data_used,
        );

        let mut hss_private_key: HssPrivateKey<H> = Default::default();

        let mut current_seed = private_key.generate_root_seed_and_lms_tree_identifier();

        let lms_keypair = generate_key_pair_with_seed_and_aux(
            &current_seed,
            &parameters[0],
            &used_leafs_indexes[0],
            &mut expanded_aux_data,
        );

        hss_private_key.private_key.push(lms_keypair.private_key);
        hss_private_key.public_key.push(lms_keypair.public_key);

        for i in 1..levels {
            let parameter = &parameters[i];

            let parent_used_leafs_index: u32 =
                hss_private_key.private_key[i - 1].used_leafs_index as u32;
            current_seed = generate_child_seed_and_lms_tree_identifier(
                &current_seed,
                &parent_used_leafs_index,
            );

            let lms_keypair = generate_key_pair_with_seed_and_aux(
                &current_seed,
                parameter,
                &used_leafs_indexes[i],
                &mut None,
            );

            hss_private_key.private_key.push(lms_keypair.private_key);
            hss_private_key.public_key.push(lms_keypair.public_key);

            let signature_randomizer = Some(
                ArrayVec::try_from(generate_child_signature_randomizer(
                    &current_seed,
                    &parent_used_leafs_index,
                ))
                .unwrap(),
            );
            let signature = lms::signing::LmsSignature::sign(
                &mut hss_private_key.private_key[i - 1],
                hss_private_key.public_key[i]
                    .to_binary_representation()
                    .as_slice(),
                signature_randomizer,
            )?;

            hss_private_key.signatures.push(signature);
        }

        if let Some(expanded_aux_data) = expanded_aux_data.as_mut() {
            if !is_aux_data_used {
                hss_finalize_aux_data::<H>(expanded_aux_data, &private_key.seed);
            }
        }

        Ok(hss_private_key)
    }

    fn get_expanded_aux_data<'a>(
        aux_data: Option<&'a mut &mut [u8]>,
        private_key: &'a ReferenceImplPrivateKey<H>,
        top_lms_parameter: &LmsParameter<H>,
        is_aux_data_used: bool,
    ) -> Option<MutableExpandedAuxData<'a>> {
        if let Some(aux_data) = aux_data {
            if is_aux_data_used {
                hss_expand_aux_data::<H>(Some(aux_data), Some(&private_key.seed))
            } else {
                let aux_len = hss_get_aux_data_len(aux_data.len(), *top_lms_parameter);

                // Shrink input slice
                let moved = core::mem::replace(aux_data, &mut []);
                *aux_data = &mut moved[..aux_len];

                let aux_level = hss_optimal_aux_level(aux_len, *top_lms_parameter, None);
                hss_store_aux_marker(aux_data, aux_level);

                hss_expand_aux_data::<H>(Some(aux_data), None)
            }
        } else {
            None
        }
    }

    pub fn get_public_key(&self) -> HssPublicKey<H> {
        HssPublicKey {
            public_key: self.public_key[0].clone(),
            level: self.get_length(),
        }
    }

    pub fn get_lifetime(&self) -> u64 {
        let mut lifetime: u64 = 0;
        let mut trees_total_lmots_keys: ArrayVec<u64, MAX_ALLOWED_HSS_LEVELS> = ArrayVec::new();

        for lms_private_key in (&self.private_key).into_iter().rev() {
            let total_lmots_keys = lms_private_key.lms_parameter.number_of_lm_ots_keys() as u64;
            let mut free_lmots_keys = total_lmots_keys - lms_private_key.used_leafs_index as u64;

            // For the intermediate and root trees all other trees on top need to be taken into
            // account. Thus, the top tree total count needs to be multiplied with free leafs of
            // the current level.
            for subtree_total_lmots_keys in &trees_total_lmots_keys {
                free_lmots_keys *= subtree_total_lmots_keys;
            }
            trees_total_lmots_keys.push(total_lmots_keys);

            lifetime += free_lmots_keys;
        }
        lifetime
    }
}

#[derive(PartialEq)]
pub struct HssPublicKey<H: Hasher> {
    pub public_key: LmsPublicKey<H>,
    pub level: usize,
}

/// To reduce memory footprint on verification we handle the public key in-memory using ```InMemoryHssPublicKey```.
/// In order to reduce complexity we use ```HssPublicKey``` for key generation and signature generation.
pub struct InMemoryHssPublicKey<'a, H: Hasher> {
    pub public_key: InMemoryLmsPublicKey<'a, H>,
    pub level: usize,
}

impl<'a, H: Hasher> PartialEq<HssPublicKey<H>> for InMemoryHssPublicKey<'a, H> {
    fn eq(&self, other: &HssPublicKey<H>) -> bool {
        self.public_key == other.public_key && self.level == other.level
    }
}

impl<H: Hasher> HssPublicKey<H> {
    pub fn to_binary_representation(&self) -> ArrayVec<u8, { 4 + MAX_LMS_PUBLIC_KEY_LENGTH }> {
        let mut result = ArrayVec::new();

        result
            .try_extend_from_slice(&u32str(self.level as u32))
            .unwrap();
        result
            .try_extend_from_slice(self.public_key.to_binary_representation().as_slice())
            .unwrap();

        result
    }
}

impl<'a, H: Hasher> InMemoryHssPublicKey<'a, H> {
    pub fn new(data: &'a [u8]) -> Option<Self> {
        let mut index = 0;

        let level = str32u(read_and_advance(data, 4, &mut index));

        let public_key = match InMemoryLmsPublicKey::new(&data[index..]) {
            None => return None,
            Some(x) => x,
        };

        Some(Self {
            public_key,
            level: level as usize,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::{HssPrivateKey, HssPublicKey};
    use crate::hasher::sha256::Sha256Hasher;
    use crate::hss::definitions::InMemoryHssPublicKey;
    use crate::{
        hss::reference_impl_private_key::ReferenceImplPrivateKey, Hasher, HssParameter,
        LmotsAlgorithm, LmsAlgorithm,
    };

    #[test]
    fn child_tree_lms_leaf_update() {
        type H = Sha256Hasher;
        let (hss_key, hss_key_second) = tree_lms_leaf_update::<H>(1);

        // 1 increment of the key updates the leaf in the top child tree.
        // This updates the private key of the top child tree.
        assert_eq!(hss_key.private_key[0], hss_key_second.private_key[0]);
        assert_eq!(hss_key.public_key[0], hss_key_second.public_key[0]);
        assert_eq!(hss_key.signatures[0], hss_key_second.signatures[0]);

        assert_eq!(hss_key.private_key[1], hss_key_second.private_key[1]);
        assert_eq!(hss_key.public_key[1], hss_key_second.public_key[1]);
        assert_eq!(hss_key.signatures[1], hss_key_second.signatures[1]);

        assert_ne!(hss_key.private_key[2], hss_key_second.private_key[2]);
        assert_eq!(hss_key.public_key[2], hss_key_second.public_key[2]);
    }

    #[test]
    fn intermediate_tree_lms_leaf_update() {
        type H = Sha256Hasher;
        let (hss_key, hss_key_second) = tree_lms_leaf_update::<H>(4);

        // 4 increments of the key updates leafs in the top child tree and the intermediate
        // child tree.
        // This updates the private and public key of the top child tree, as the top child tree is
        // exhausted (with a tree heigth of two). Thus, the intermediate child tree is updated as
        // well with the effect of a changed private key and a new intermediate signature for the
        // new top child tree signed by the update intermediate private key.
        assert_eq!(hss_key.private_key[0], hss_key_second.private_key[0]);
        assert_eq!(hss_key.public_key[0], hss_key_second.public_key[0]);
        assert_eq!(hss_key.signatures[0], hss_key_second.signatures[0]);

        assert_ne!(hss_key.private_key[1], hss_key_second.private_key[1]);
        assert_eq!(hss_key.public_key[1], hss_key_second.public_key[1]);
        assert_ne!(hss_key.signatures[1], hss_key_second.signatures[1]);

        assert_ne!(hss_key.private_key[2], hss_key_second.private_key[2]);
        assert_ne!(hss_key.public_key[2], hss_key_second.public_key[2]);
    }

    #[test]
    fn root_tree_lms_leaf_update() {
        type H = Sha256Hasher;
        let (hss_key, hss_key_second) = tree_lms_leaf_update::<H>(16);

        // 16 increments of the key updates leafs in the top child tree, the intermediate
        // child tree and the root tree.
        // Top and intermediate child tree are exhausted and the root tree is updated. Thus top
        // child tree private and public key is updated together with the intermediate signature
        // and further intermediate tree private and public key is updated together with the
        // intermediate signature. Root tree private key is updated as the leaf is switched.
        assert_ne!(hss_key.private_key[0], hss_key_second.private_key[0]);
        assert_eq!(hss_key.public_key[0], hss_key_second.public_key[0]);
        assert_ne!(hss_key.signatures[0], hss_key_second.signatures[0]);

        assert_ne!(hss_key.private_key[1], hss_key_second.private_key[1]);
        assert_ne!(hss_key.public_key[1], hss_key_second.public_key[1]);
        assert_ne!(hss_key.signatures[1], hss_key_second.signatures[1]);

        assert_ne!(hss_key.private_key[2], hss_key_second.private_key[2]);
        assert_ne!(hss_key.public_key[2], hss_key_second.public_key[2]);
    }

    fn tree_lms_leaf_update<H: 'static + Hasher>(
        increment_by: u8,
    ) -> (HssPrivateKey<H>, HssPrivateKey<H>) {
        let lmots = LmotsAlgorithm::LmotsW4;
        let lms = LmsAlgorithm::LmsH2;
        let parameters = [
            HssParameter::<H>::new(lmots, lms),
            HssParameter::<H>::new(lmots, lms),
            HssParameter::<H>::new(lmots, lms),
        ];

        let mut rfc_key = ReferenceImplPrivateKey::generate(&parameters).unwrap();

        let hss_key_before = HssPrivateKey::from(&rfc_key, None).unwrap();

        for _ in 0..increment_by {
            rfc_key.increment(&hss_key_before);
        }

        let hss_key_after = HssPrivateKey::from(&rfc_key, None).unwrap();

        (hss_key_before, hss_key_after)
    }

    #[test]
    fn lifetime() {
        type H = Sha256Hasher;

        let lmots = LmotsAlgorithm::LmotsW4;
        let lms = LmsAlgorithm::LmsH2;
        let parameters = [
            HssParameter::<H>::new(lmots, lms),
            HssParameter::<H>::new(lmots, lms),
            HssParameter::<H>::new(lmots, lms),
        ];

        let mut private_key = ReferenceImplPrivateKey::generate(&parameters).unwrap();
        let hss_key = HssPrivateKey::from(&private_key, None).unwrap();

        let tree_heights = hss_key
            .public_key
            .iter()
            .map(|pk| pk.lms_parameter.get_tree_height());
        let total_ots_count = 2u64.pow(tree_heights.clone().sum::<u8>().into());

        assert_eq!(hss_key.get_lifetime(), total_ots_count,);

        const STEP_BY: usize = 27;
        for index in (0..total_ots_count).step_by(STEP_BY) {
            let hss_key = HssPrivateKey::from(&private_key, None).unwrap();

            assert_eq!(hss_key.get_lifetime(), total_ots_count - index,);

            for _ in 0..STEP_BY {
                private_key.increment(&hss_key);
            }
        }
    }

    #[test]
    fn deterministic_signed_public_key_signatures() {
        type H = Sha256Hasher;

        let lmots = LmotsAlgorithm::LmotsW4;
        let lms = LmsAlgorithm::LmsH2;
        let parameters = [
            HssParameter::<H>::new(lmots, lms),
            HssParameter::<H>::new(lmots, lms),
        ];

        let private_key = ReferenceImplPrivateKey::generate(&parameters).unwrap();

        let hss_key = HssPrivateKey::from(&private_key, None).unwrap();
        let hss_key_second = HssPrivateKey::from(&private_key, None).unwrap();
        assert_eq!(hss_key, hss_key_second);
    }

    #[test]
    fn test_public_key_binary_representation() {
        let public_key =
            crate::lms::generate_key_pair(&HssParameter::construct_default_parameters());
        let public_key: HssPublicKey<Sha256Hasher> = HssPublicKey {
            level: 18,
            public_key: public_key.public_key,
        };

        let binary_representation = public_key.to_binary_representation();

        let deserialized = InMemoryHssPublicKey::new(binary_representation.as_slice())
            .expect("Deserialization should work.");

        assert!(deserialized == public_key);
    }
}
