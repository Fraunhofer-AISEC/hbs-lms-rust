use crate::constants::MAX_HASH;
use crate::hasher::Hasher;
use crate::util::dynamic_array::DynamicArray;
use crate::{
    constants::{D_INTR, D_LEAF},
    util::ustr::u32str,
};

use super::definitions::LmsPrivateKey;

pub fn get_tree_element<H: Hasher>(
    index: usize,
    private_key: &LmsPrivateKey<H>,
) -> DynamicArray<u8, MAX_HASH> {
    let mut hasher = <H>::get_hasher();

    hasher.update(&private_key.I);
    hasher.update(&u32str(index as u32));

    let max_private_keys = private_key.lms_parameter.number_of_lm_ots_keys();

    if index >= max_private_keys {
        hasher.update(&D_LEAF);
        let lms_ots_private_key = crate::lm_ots::generate_private_key(
            u32str((index - max_private_keys) as u32),
            private_key.I,
            private_key.seed,
            private_key.lmots_parameter,
        );

        let lm_ots_public_key = crate::lm_ots::generate_public_key(&lms_ots_private_key);
        hasher.update(&lm_ots_public_key.key.as_slice());
    } else {
        hasher.update(&D_INTR);
        let left = get_tree_element(2 * index, private_key);
        let right = get_tree_element(2 * index + 1, private_key);

        hasher.update(&left.as_slice());
        hasher.update(&right.as_slice());
    }

    hasher.finalize()
}
