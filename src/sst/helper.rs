use crate::hss::reference_impl_private_key::ReferenceImplPrivateKey;
use crate::lms::parameters::LmsParameter;
use crate::signature::Error;
use crate::sst::parameters::SstExtension;
use crate::HashChain;

// Returns the sub-tree root node index within a LMS with SST extension
// signing_entity_idx counts from left-most = 1 to right-most = total number of sub-trees
// sub-tree root node index starts with offset of 0
pub fn get_sst_root_node_idx<H: HashChain>(
    lms_parameter: &LmsParameter<H>,
    sst_extension: &SstExtension,
) -> u32 {
    assert!(sst_extension.l0_top_div() <= lms_parameter.get_tree_height());
    2u32.pow(sst_extension.l0_top_div() as u32) + (sst_extension.signing_entity_idx() as u32) - 1
}

fn get_sst_number_of_lm_ots_keys<H: HashChain>(
    lms_parameter: &LmsParameter<H>,
    sst_extension: &SstExtension,
) -> u32 {
    assert!(sst_extension.l0_top_div() <= lms_parameter.get_tree_height());
    2u32.pow((lms_parameter.get_tree_height() - sst_extension.l0_top_div()) as u32)
}

// For a subtree, depending on whole SSTS and division, get first leaf idx where leafs start with 0
pub fn get_sst_first_leaf_idx<H: HashChain>(
    lms_parameter: &LmsParameter<H>,
    sst_extension: &SstExtension,
) -> u32 {
    ((sst_extension.signing_entity_idx() as u32) - 1)
        * get_sst_number_of_lm_ots_keys(lms_parameter, sst_extension)
}

// For a subtree, depending on whole SSTS and division, get last leaf idx where leafs start with 0
pub fn get_sst_last_leaf_idx<H: HashChain>(
    lms_parameter: &LmsParameter<H>,
    sst_extension: &SstExtension,
) -> u32 {
    get_sst_first_leaf_idx(lms_parameter, sst_extension)
        + get_sst_number_of_lm_ots_keys(lms_parameter, sst_extension)
        - 1
}

pub fn get_num_signing_entities<H: HashChain>(private_key: &[u8]) -> Result<u32, Error> {
    let rfc_private_key = ReferenceImplPrivateKey::<H>::from_binary_representation(private_key)
        .map_err(|_| Error::new())?;

    if let Some(sst_extension) = &rfc_private_key.sst_option {
        Ok(2u32.pow(sst_extension.l0_top_div() as u32))
    } else {
        Err(Error::new())
    }
}

#[cfg(test)]
mod tests {

    use super::*;
    use crate::lms::parameters::LmsAlgorithm;
    use crate::util::helper::test_helper::gen_random_seed;
    use crate::HssParameter;
    use crate::Sha256_128;

    #[test]
    fn test_get_sst_root_node_idx_1() {
        let lms_parameter = LmsAlgorithm::get_from_type::<Sha256_128>(5).unwrap();
        let sst_extension = SstExtension::new(1, 2).unwrap();
        let subtree_node_idx = get_sst_root_node_idx(&lms_parameter, &sst_extension);
        assert_eq!(4, subtree_node_idx);
    }

    #[test]
    fn test_get_sst_root_node_idx_2() {
        let lms_parameter = LmsAlgorithm::get_from_type::<Sha256_128>(5).unwrap();
        let sst_extension = SstExtension::new(2, 2).unwrap();
        let subtree_node_idx = get_sst_root_node_idx(&lms_parameter, &sst_extension);
        assert_eq!(5, subtree_node_idx);
    }

    #[test]
    fn test_get_sst_root_node_idx_3() {
        let lms_parameter = LmsAlgorithm::get_from_type::<Sha256_128>(5).unwrap();
        let sst_extension = SstExtension::new(1, 3).unwrap();
        let subtree_node_idx = get_sst_root_node_idx(&lms_parameter, &sst_extension);
        assert_eq!(8, subtree_node_idx);
    }

    #[test]
    fn test_get_sst_root_node_idx_4() {
        let lms_parameter = LmsAlgorithm::get_from_type::<Sha256_128>(5).unwrap();
        let sst_extension = SstExtension::new(2, 3).unwrap();
        let subtree_node_idx = get_sst_root_node_idx(&lms_parameter, &sst_extension);
        assert_eq!(9, subtree_node_idx);
    }

    #[test]
    fn test_get_sst_root_node_idx_5() {
        let lms_parameter = LmsAlgorithm::get_from_type::<Sha256_128>(5).unwrap();
        let sst_extension = SstExtension::new(1, 4).unwrap();
        let subtree_node_idx = get_sst_root_node_idx(&lms_parameter, &sst_extension);
        assert_eq!(16, subtree_node_idx);
    }

    #[test]
    fn test_get_sst_root_node_idx_6() {
        let lms_parameter = LmsAlgorithm::get_from_type::<Sha256_128>(5).unwrap();
        let sst_extension = SstExtension::new(9, 4).unwrap();
        let subtree_node_idx = get_sst_root_node_idx(&lms_parameter, &sst_extension);
        assert_eq!(24, subtree_node_idx);
    }

    // one outermost "leaf"
    #[test]
    fn test_get_sst_root_node_idx_7() {
        let lms_parameter = LmsAlgorithm::get_from_type::<Sha256_128>(5).unwrap();
        let sst_extension = SstExtension::new(16, 4).unwrap();
        let subtree_node_idx = get_sst_root_node_idx(&lms_parameter, &sst_extension);
        assert_eq!(31, subtree_node_idx);
    }

    // wrong config, subtree_node_idx too high
    #[test]
    #[should_panic]
    fn test_get_sst_root_node_idx_8() {
        let lms_parameter = LmsAlgorithm::get_from_type::<Sha256_128>(5).unwrap();
        let sst_extension = SstExtension::new(17, 4).unwrap();
        let _subtree_node_idx = get_sst_root_node_idx(&lms_parameter, &sst_extension);
    }

    #[test]
    fn test_get_sst_number_of_lm_ots_keys_1() {
        let lms_parameter = LmsAlgorithm::get_from_type::<Sha256_128>(5).unwrap();
        let sst_extension = SstExtension::new(16, 4).unwrap();
        let num_lm_ots_keys = get_sst_number_of_lm_ots_keys(&lms_parameter, &sst_extension);
        assert_eq!(2, num_lm_ots_keys);
    }

    #[test]
    #[should_panic]
    fn test_get_sst_number_of_lm_ots_keys_2() {
        let lms_parameter = LmsAlgorithm::get_from_type::<Sha256_128>(5).unwrap();
        let sst_extension = SstExtension::new(16, 6).unwrap();
        let _num_lm_ots_keys = get_sst_number_of_lm_ots_keys(&lms_parameter, &sst_extension);
    }

    #[test]
    fn test_get_sst_first_leaf_idx_1() {
        let lms_parameter = LmsAlgorithm::get_from_type::<Sha256_128>(5).unwrap();
        let sst_extension = SstExtension::new(4, 3).unwrap();
        let first_leaf_idx = get_sst_first_leaf_idx(&lms_parameter, &sst_extension);
        assert_eq!(12, first_leaf_idx);
    }

    #[test]
    fn test_get_sst_first_leaf_idx_2() {
        let lms_parameter = LmsAlgorithm::get_from_type::<Sha256_128>(5).unwrap();
        let sst_extension = SstExtension::new(4, 4).unwrap();
        let first_leaf_idx = get_sst_first_leaf_idx(&lms_parameter, &sst_extension);
        assert_eq!(6, first_leaf_idx);
    }

    #[test]
    fn test_get_sst_last_leaf_idx_1() {
        let lms_parameter = LmsAlgorithm::get_from_type::<Sha256_128>(5).unwrap();
        let sst_extension = SstExtension::new(4, 3).unwrap();
        let first_leaf_idx = get_sst_last_leaf_idx(&lms_parameter, &sst_extension);
        assert_eq!(15, first_leaf_idx);
    }

    #[test]
    fn test_get_sst_last_leaf_idx_2() {
        let lms_parameter = LmsAlgorithm::get_from_type::<Sha256_128>(5).unwrap();
        let sst_extension = SstExtension::new(4, 4).unwrap();
        let first_leaf_idx = get_sst_last_leaf_idx(&lms_parameter, &sst_extension);
        assert_eq!(7, first_leaf_idx);
    }

    #[test]
    fn test_get_num_signing_entities_1() {
        let seed = gen_random_seed::<Sha256_128>();
        let sst_extension = SstExtension::new(4, 3).unwrap();
        let rfc_private_key = ReferenceImplPrivateKey::<Sha256_128>::generate(
            &[
                HssParameter::construct_default_parameters(),
                HssParameter::construct_default_parameters(),
            ],
            &seed,
            Some(sst_extension),
        )
        .unwrap();
        let private_key = rfc_private_key.to_binary_representation();
        let num_se = get_num_signing_entities::<Sha256_128>(&private_key).unwrap();
        assert_eq!(8, num_se);
    }

    #[test]
    #[should_panic]
    fn test_get_num_signing_entities_2() {
        let seed = gen_random_seed::<Sha256_128>();
        let rfc_private_key = ReferenceImplPrivateKey::<Sha256_128>::generate(
            &[
                HssParameter::construct_default_parameters(),
                HssParameter::construct_default_parameters(),
            ],
            &seed,
            None,
        )
        .unwrap();
        let private_key = rfc_private_key.to_binary_representation();
        let _num_se = get_num_signing_entities::<Sha256_128>(&private_key).unwrap();
    }
}
