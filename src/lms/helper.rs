use crate::constants::MAX_HASH_SIZE;
use crate::hasher::Hasher;
use crate::hss::aux::{hss_extract_aux_data, hss_save_aux_data, MutableExpandedAuxData};
use crate::{
    constants::{D_INTR, D_LEAF},
    util::ustr::u32str,
};
use arrayvec::ArrayVec;

use super::definitions::LmsPrivateKey;

pub fn get_tree_element<H: Hasher>(
    index: usize,
    private_key: &LmsPrivateKey<H>,
    aux_data: &mut Option<MutableExpandedAuxData>,
) -> ArrayVec<u8, MAX_HASH_SIZE> {
    // Check if we already have the value cached
    if let Some(aux_data) = aux_data {
        if let Some(result) = hss_extract_aux_data::<H>(aux_data, index) {
            return result;
        }
    }

    let mut hasher = <H>::get_hasher();

    hasher.update(&private_key.lms_tree_identifier);
    hasher.update(&u32str(index as u32));

    let max_private_keys = private_key.lms_parameter.number_of_lm_ots_keys();

    if index >= max_private_keys {
        hasher.update(&D_LEAF);
        let lms_ots_private_key = crate::lm_ots::generate_private_key(
            u32str((index - max_private_keys) as u32),
            private_key.lms_tree_identifier,
            private_key.seed,
            private_key.lmots_parameter,
        );

        let lm_ots_public_key = crate::lm_ots::generate_public_key(&lms_ots_private_key);
        hasher.update(lm_ots_public_key.key.as_slice());
    } else {
        hasher.update(&D_INTR);
        let left = get_tree_element(2 * index, private_key, aux_data);
        let right = get_tree_element(2 * index + 1, private_key, aux_data);

        hasher.update(left.as_slice());
        hasher.update(right.as_slice());
    }

    let result = hasher.finalize();

    if let Some(expanded_aux_data) = aux_data.as_mut() {
        hss_save_aux_data::<H>(expanded_aux_data, index, result.as_slice());
    }

    result
}
