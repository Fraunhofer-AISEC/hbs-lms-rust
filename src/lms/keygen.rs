use super::helper::get_tree_element;
use crate::definitions::MAX_M;
use crate::definitions::MAX_TREE_ELEMENTS;
use crate::lm_ots::definitions::IType;
use crate::lm_ots::definitions::LmotsAlgorithmType;
use crate::lm_ots::definitions::Seed;
use crate::lms::definitions::LmsAlgorithmType;
use crate::lms::definitions::LmsPrivateKey;
use crate::lms::definitions::LmsPublicKey;
use crate::util::dynamic_array::DynamicArray;
use crate::util::helper::is_power_of_two;

pub fn generate_private_key(
    lms_type: LmsAlgorithmType,
    lmots_type: LmotsAlgorithmType,
) -> LmsPrivateKey {
    let mut i: IType = [0u8; 16];
    crate::util::random::get_random(&mut i);

    let mut seed: Seed = [0u8; 32];
    crate::util::random::get_random(&mut seed);

    LmsPrivateKey::new(lms_type, lmots_type, seed, i)
}

pub fn generate_public_key(private_key: &LmsPrivateKey) -> LmsPublicKey {
    let lms_parameter = private_key.lms_type.get_parameter();
    let num_lmots_keys = private_key.lms_type.get_parameter().number_of_lm_ots_keys();

    // num_lmots_keys must be a power of two
    assert!(is_power_of_two(num_lmots_keys));

    let max_private_keys = 2_usize.pow(lms_parameter.h.into());

    let mut temp_hash_tree: [Option<[u8; MAX_M]>; MAX_TREE_ELEMENTS + 1] =
        [None; MAX_TREE_ELEMENTS + 1]; // Use index + 1 to start accessing at 1

    let public_key = get_tree_element(&mut temp_hash_tree, 1, max_private_keys, private_key);

    let mut hash_tree = DynamicArray::new();

    for (index, temp_hash) in temp_hash_tree.iter().enumerate() {
        let value = temp_hash.unwrap_or([0u8; 32]);
        hash_tree[index] = DynamicArray::from_slice(&value);
    }

    LmsPublicKey::new(
        DynamicArray::from_slice(&public_key),
        hash_tree,
        private_key.lm_ots_type,
        private_key.lms_type,
        private_key.I,
    )
}
