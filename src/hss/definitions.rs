use core::convert::TryInto;

use tinyvec::ArrayVec;

use crate::{
    constants::{
        LmsTreeIdentifier, Node, MAX_ALLOWED_HSS_LEVELS, MAX_HSS_PUBLIC_KEY_LENGTH,
        MAX_SSTS_SIGNING_ENTITIES,
    },
    hasher::HashChain,
    hss::aux::{
        hss_expand_aux_data, hss_finalize_aux_data, hss_get_aux_data_len, hss_is_aux_data_used,
        hss_optimal_aux_level, hss_save_aux_data, hss_store_aux_marker, MutableExpandedAuxData,
    },
    lms::{
        self,
        definitions::{InMemoryLmsPublicKey, LmsPrivateKey, LmsPublicKey},
        generate_key_pair,
        parameters::LmsParameter,
        signing::LmsSignature,
    },
    sst::helper::get_sst_root_node_idx,
    sst::parameters::SstExtension,
    util::helper::read_and_advance,
};

use super::reference_impl_private_key::{
    generate_child_seed_and_lms_tree_identifier, generate_signature_randomizer,
    ReferenceImplPrivateKey,
};

#[derive(Debug, Default, PartialEq)]
pub struct HssPrivateKey<H: HashChain> {
    pub private_key: ArrayVec<[LmsPrivateKey<H>; MAX_ALLOWED_HSS_LEVELS]>,
    pub public_key: ArrayVec<[LmsPublicKey<H>; MAX_ALLOWED_HSS_LEVELS - 1]>,
    pub signatures: ArrayVec<[LmsSignature<H>; MAX_ALLOWED_HSS_LEVELS - 1]>, // Only L - 1 signatures needed
}

impl<H: HashChain> HssPrivateKey<H> {
    pub fn get_length(&self) -> usize {
        self.private_key.len()
    }

    pub fn from(
        private_key: &ReferenceImplPrivateKey<H>,
        aux_data: &mut Option<MutableExpandedAuxData>,
        tree_identifier: Option<&LmsTreeIdentifier>,
    ) -> Result<Self, ()> {
        let mut hss_private_key: HssPrivateKey<H> = Default::default();

        let mut current_seed = private_key.generate_root_seed_and_lms_tree_identifier();

        if let Some(tree_identifier) = tree_identifier {
            current_seed
                .lms_tree_identifier
                .clone_from_slice(tree_identifier);
        }

        let parameters = private_key.compressed_parameter.to::<H>()?;
        let used_leafs_indexes = private_key.compressed_used_leafs_indexes.to(&parameters);

        let lms_private_key = LmsPrivateKey {
            seed: current_seed.seed.clone(),
            lms_tree_identifier: current_seed.lms_tree_identifier,
            lmots_parameter: *parameters[0].get_lmots_parameter(),
            lms_parameter: *parameters[0].get_lms_parameter(),
            used_leafs_index: used_leafs_indexes[0],
            sst_option: private_key.sst_option.clone(),
        };
        hss_private_key.private_key.push(lms_private_key);

        for (i, parameter) in parameters.iter().enumerate().skip(1) {
            let parent_used_leafs_index: u32 = hss_private_key.private_key[i - 1].used_leafs_index;

            current_seed = generate_child_seed_and_lms_tree_identifier::<H>(
                &current_seed,
                &parent_used_leafs_index,
            );
            let signature_randomizer =
                generate_signature_randomizer::<H>(&current_seed, &parent_used_leafs_index);

            let lms_keypair = generate_key_pair(
                &current_seed,
                parameter,
                &used_leafs_indexes[i],
                &mut None,
                None,
            );

            let signature = lms::signing::LmsSignature::sign(
                &mut hss_private_key.private_key[i - 1],
                lms_keypair.public_key.to_binary_representation().as_slice(),
                &signature_randomizer,
                aux_data,
            )?;
            *aux_data = None;

            hss_private_key.private_key.push(lms_keypair.private_key);
            hss_private_key.public_key.push(lms_keypair.public_key);
            hss_private_key.signatures.push(signature);
        }

        Ok(hss_private_key)
    }

    pub fn get_expanded_aux_data<'a>(
        aux_data: Option<&'a mut &mut [u8]>,
        private_key: &'a ReferenceImplPrivateKey<H>,
        top_lms_parameter: &LmsParameter<H>,
        is_aux_data_used: bool,
    ) -> Option<MutableExpandedAuxData<'a>> {
        let aux_data = aux_data?;

        if is_aux_data_used {
            // has been created, shrinked, populated and provided with HMAC before
            return hss_expand_aux_data::<H>(Some(aux_data), Some(private_key.seed.as_slice()));
        }

        let opt_l0_top_div = private_key
            .sst_option
            .as_ref()
            .map(|sst_extension| sst_extension.l0_top_div());

        // Shrink input slice
        let aux_len = hss_get_aux_data_len(aux_data.len(), *top_lms_parameter, opt_l0_top_div);
        let moved = core::mem::take(aux_data);
        *aux_data = &mut moved[..aux_len];

        let aux_level = hss_optimal_aux_level(aux_len, *top_lms_parameter, None, opt_l0_top_div);
        hss_store_aux_marker(aux_data, aux_level);

        hss_expand_aux_data::<H>(Some(aux_data), None)
    }

    pub fn get_lifetime(&self) -> u64 {
        let mut lifetime: u64 = 0;
        let mut trees_total_lmots_keys: ArrayVec<[u64; MAX_ALLOWED_HSS_LEVELS]> = ArrayVec::new();

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

#[derive(PartialEq, Eq)]
pub struct HssPublicKey<H: HashChain> {
    pub public_key: LmsPublicKey<H>,
    pub level: usize,
}

/// To reduce memory footprint on verification we handle the public key in-memory using ```InMemoryHssPublicKey```.
/// In order to reduce complexity we use ```HssPublicKey``` for key generation and signature generation.
pub struct InMemoryHssPublicKey<'a, H: HashChain> {
    pub public_key: InMemoryLmsPublicKey<'a, H>,
    pub level: usize,
}

impl<'a, H: HashChain> PartialEq<HssPublicKey<H>> for InMemoryHssPublicKey<'a, H> {
    fn eq(&self, other: &HssPublicKey<H>) -> bool {
        self.public_key == other.public_key && self.level == other.level
    }
}

impl<H: HashChain> HssPublicKey<H> {
    pub fn from(
        private_key: &ReferenceImplPrivateKey<H>,
        aux_data: Option<&mut &mut [u8]>,
    ) -> Result<Self, ()> {
        let parameters = private_key.compressed_parameter.to::<H>()?;
        let levels = parameters.len();
        let used_leafs_indexes = private_key.compressed_used_leafs_indexes.to(&parameters);

        let top_lms_parameter = parameters[0].get_lms_parameter();

        let is_aux_data_used = aux_data.as_ref().map_or(false, |d| hss_is_aux_data_used(d));

        let mut expanded_aux_data = HssPrivateKey::get_expanded_aux_data(
            aux_data,
            private_key,
            top_lms_parameter,
            is_aux_data_used,
        );

        let current_seed = private_key.generate_root_seed_and_lms_tree_identifier();

        let lms_keypair = generate_key_pair(
            &current_seed,
            &parameters[0],
            &used_leafs_indexes[0],
            &mut expanded_aux_data,
            None,
        );

        if let Some(expanded_aux_data) = expanded_aux_data.as_mut() {
            if !is_aux_data_used {
                hss_finalize_aux_data::<H>(expanded_aux_data, private_key.seed.as_slice());
            }
        }

        Ok(Self {
            public_key: lms_keypair.public_key,
            level: levels,
        })
    }

    pub fn from_with_sst(
        private_key: &ReferenceImplPrivateKey<H>,
        aux_data: Option<&mut &mut [u8]>,
        intermed_nodes: &ArrayVec<[Node; MAX_SSTS_SIGNING_ENTITIES]>,
        tree_identifier: &LmsTreeIdentifier,
    ) -> Result<Self, ()> {
        let sst_extension = private_key.sst_option.as_ref().ok_or(())?;

        let parameters = private_key.compressed_parameter.to::<H>()?;
        let used_leafs_indexes = private_key.compressed_used_leafs_indexes.to(&parameters);

        let top_lms_parameter = parameters[0].get_lms_parameter();

        let is_aux_data_used = aux_data.as_ref().map_or(false, |d| hss_is_aux_data_used(d));
        let mut opt_expanded_aux_data = HssPrivateKey::get_expanded_aux_data(
            aux_data,
            private_key,
            top_lms_parameter,
            is_aux_data_used,
        );

        let mut current_seed = private_key.generate_root_seed_and_lms_tree_identifier();
        current_seed
            .lms_tree_identifier
            .copy_from_slice(tree_identifier);

        // Move intermed_nodes, i.e. other subtree root nodes, into aux_data
        (intermed_nodes.len() == 2usize.pow(sst_extension.l0_top_div().into()))
            .then_some(())
            .ok_or(())?;
        for (se_node, se_idx) in intermed_nodes.iter().zip(1..=intermed_nodes.len() as u8) {
            let si_sst_ext =
                SstExtension::new(se_idx, sst_extension.l0_top_div()).map_err(|_| ())?;
            let node_idx = get_sst_root_node_idx(top_lms_parameter, &si_sst_ext) as usize;
            hss_save_aux_data::<H>(opt_expanded_aux_data.as_mut().ok_or(())?, node_idx, se_node);
        }

        // Calculate public key with the help of the aux_data containing other subtree root nodes
        let lms_keypair = generate_key_pair(
            &current_seed,
            &parameters[0],
            &used_leafs_indexes[0],
            &mut opt_expanded_aux_data,
            None,
        );

        // Finalize aux_data by updating the HMAC
        hss_finalize_aux_data::<H>(
            opt_expanded_aux_data.as_mut().ok_or(())?,
            private_key.seed.as_slice(),
        );

        Ok(Self {
            public_key: lms_keypair.public_key,
            level: parameters.len(),
        })
    }

    pub fn to_binary_representation(&self) -> ArrayVec<[u8; MAX_HSS_PUBLIC_KEY_LENGTH]> {
        let mut result = ArrayVec::new();

        result.extend_from_slice(&(self.level as u32).to_be_bytes());
        result.extend_from_slice(self.public_key.to_binary_representation().as_slice());

        result
    }
}

impl<'a, H: HashChain> InMemoryHssPublicKey<'a, H> {
    pub fn new(data: &'a [u8]) -> Option<Self> {
        let mut index = 0;

        let level = u32::from_be_bytes(read_and_advance(data, 4, &mut index).try_into().unwrap());

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
    use rand::{rngs::OsRng, RngCore};

    use crate::util::helper::test_helper::gen_random_seed;
    use crate::{
        hasher::sha256::Sha256_256,
        hss::{
            definitions::InMemoryHssPublicKey,
            reference_impl_private_key::{ReferenceImplPrivateKey, SeedAndLmsTreeIdentifier},
            HashChain,
        },
        lms, HssParameter, LmotsAlgorithm, LmsAlgorithm,
    };

    use super::{HssPrivateKey, HssPublicKey};

    #[test]
    fn child_tree_lms_leaf_update() {
        type H = Sha256_256;
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
    }

    #[test]
    fn intermediate_tree_lms_leaf_update() {
        type H = Sha256_256;
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
        assert_ne!(hss_key.public_key[1], hss_key_second.public_key[1]);
        assert_ne!(hss_key.signatures[1], hss_key_second.signatures[1]);

        assert_ne!(hss_key.private_key[2], hss_key_second.private_key[2]);
    }

    #[test]
    fn root_tree_lms_leaf_update() {
        type H = Sha256_256;
        let (hss_key, hss_key_second) = tree_lms_leaf_update::<H>(16);

        // 16 increments of the key updates leafs in the top child tree, the intermediate
        // child tree and the root tree.
        // Top and intermediate child tree are exhausted and the root tree is updated. Thus top
        // child tree private and public key is updated together with the intermediate signature
        // and further intermediate tree private and public key is updated together with the
        // intermediate signature. Root tree private key is updated as the leaf is switched.
        assert_ne!(hss_key.private_key[0], hss_key_second.private_key[0]);
        assert_ne!(hss_key.public_key[0], hss_key_second.public_key[0]);
        assert_ne!(hss_key.signatures[0], hss_key_second.signatures[0]);

        assert_ne!(hss_key.private_key[1], hss_key_second.private_key[1]);
        assert_ne!(hss_key.public_key[1], hss_key_second.public_key[1]);
        assert_ne!(hss_key.signatures[1], hss_key_second.signatures[1]);

        assert_ne!(hss_key.private_key[2], hss_key_second.private_key[2]);
    }

    fn tree_lms_leaf_update<H: HashChain>(
        increment_by: u8,
    ) -> (HssPrivateKey<H>, HssPrivateKey<H>) {
        let lmots = LmotsAlgorithm::LmotsW4;
        let lms = LmsAlgorithm::LmsH2;
        let parameters = [
            HssParameter::<H>::new(lmots, lms),
            HssParameter::<H>::new(lmots, lms),
            HssParameter::<H>::new(lmots, lms),
        ];

        let seed = gen_random_seed::<H>();
        let mut rfc_key = ReferenceImplPrivateKey::generate(&parameters, &seed, None).unwrap();
        let hss_key_before = HssPrivateKey::from(&rfc_key, &mut None, None).unwrap();

        for _ in 0..increment_by {
            rfc_key.increment(&hss_key_before);
        }

        let hss_key_after = HssPrivateKey::from(&rfc_key, &mut None, None).unwrap();

        (hss_key_before, hss_key_after)
    }

    #[test]
    fn lifetime() {
        type H = Sha256_256;

        let lmots = LmotsAlgorithm::LmotsW4;
        let lms = LmsAlgorithm::LmsH2;
        let parameters = [
            HssParameter::<H>::new(lmots, lms),
            HssParameter::<H>::new(lmots, lms),
            HssParameter::<H>::new(lmots, lms),
        ];

        let seed = gen_random_seed::<H>();
        let mut private_key = ReferenceImplPrivateKey::generate(&parameters, &seed, None).unwrap();
        let hss_key = HssPrivateKey::from(&private_key, &mut None, None).unwrap();

        let tree_heights = hss_key
            .private_key
            .iter()
            .map(|pk| pk.lms_parameter.get_tree_height());
        let total_ots_count = 2u64.pow(tree_heights.clone().sum::<u8>().into());

        assert_eq!(hss_key.get_lifetime(), total_ots_count,);

        const STEP_BY: usize = 27;
        for index in (0..total_ots_count).step_by(STEP_BY) {
            let hss_key = HssPrivateKey::from(&private_key, &mut None, None).unwrap();

            assert_eq!(hss_key.get_lifetime(), total_ots_count - index,);

            for _ in 0..STEP_BY {
                private_key.increment(&hss_key);
            }
        }
    }

    #[test]
    fn deterministic_signed_public_key_signatures() {
        type H = Sha256_256;

        let lmots = LmotsAlgorithm::LmotsW4;
        let lms = LmsAlgorithm::LmsH2;
        let parameters = [
            HssParameter::<H>::new(lmots, lms),
            HssParameter::<H>::new(lmots, lms),
        ];

        let seed = gen_random_seed::<H>();
        let private_key = ReferenceImplPrivateKey::generate(&parameters, &seed, None).unwrap();

        let hss_key = HssPrivateKey::from(&private_key, &mut None, None).unwrap();
        let hss_key_second = HssPrivateKey::from(&private_key, &mut None, None).unwrap();
        assert_eq!(hss_key, hss_key_second);
    }

    #[test]
    fn test_public_key_binary_representation() {
        let mut seed_and_lms_tree_identifier = SeedAndLmsTreeIdentifier::default();
        OsRng.fill_bytes(seed_and_lms_tree_identifier.seed.as_mut_slice());
        let public_key = lms::generate_key_pair(
            &seed_and_lms_tree_identifier,
            &HssParameter::construct_default_parameters(),
            &0,
            &mut None,
            None,
        );
        let public_key: HssPublicKey<Sha256_256> = HssPublicKey {
            level: 18,
            public_key: public_key.public_key,
        };

        let binary_representation = public_key.to_binary_representation();

        let deserialized = InMemoryHssPublicKey::new(binary_representation.as_slice())
            .expect("Deserialization should work.");

        assert!(deserialized == public_key);
    }
}
