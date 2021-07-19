use crate::constants::MAX_HASH;
use crate::hasher::Hasher;
use crate::hss::aux::{hss_save_aux_data, MutableExpandedAuxData};
use crate::util::dynamic_array::DynamicArray;
use crate::{
    constants::{D_INTR, D_LEAF},
    util::ustr::u32str,
};

use super::definitions::LmsPrivateKey;

pub fn get_tree_element_with_aux<H: Hasher>(
    index: usize,
    private_key: &LmsPrivateKey<H>,
    aux_data: &mut Option<MutableExpandedAuxData>,
    tree_level: u8,
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
        let left = get_tree_element_with_aux(2 * index, private_key, aux_data, tree_level + 1);
        let right = get_tree_element_with_aux(2 * index + 1, private_key, aux_data, tree_level + 1);

        hasher.update(&left.as_slice());
        hasher.update(&right.as_slice());
    }

    let result = hasher.finalize();

    let index_in_tree_row: u32 = index as u32 - 2u32.pow(tree_level as u32);

    if let Some(expanded_aux_data) = aux_data.as_mut() {
        hss_save_aux_data(
            expanded_aux_data,
            tree_level,
            H::OUTPUT_SIZE,
            index_in_tree_row,
            result.as_slice(),
        );
    }

    result
}
