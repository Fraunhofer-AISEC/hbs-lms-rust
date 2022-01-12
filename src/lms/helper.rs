use tinyvec::ArrayVec;

use crate::constants::{D_INTR, D_LEAF, MAX_HASH_SIZE};
use crate::hasher::HashChain;
use crate::hss::aux::{hss_extract_aux_data, hss_save_aux_data, MutableExpandedAuxData};
use crate::lm_ots;

use super::definitions::LmsPrivateKey;

pub fn get_tree_element<H: HashChain>(
    index: usize,
    private_key: &LmsPrivateKey<H>,
    aux_data: &mut Option<MutableExpandedAuxData>,
) -> ArrayVec<[u8; MAX_HASH_SIZE]> {
    // Check if we already have the value cached
    if let Some(aux_data) = aux_data {
        if let Some(result) = hss_extract_aux_data::<H>(aux_data, index) {
            return result;
        }
    }

    let max_private_keys = private_key.lms_parameter.number_of_lm_ots_keys();

    let hasher = H::default()
        .chain(&private_key.lms_tree_identifier)
        .chain(&(index as u32).to_be_bytes());

    let result = if index >= max_private_keys {
        let lms_ots_private_key = lm_ots::keygen::generate_private_key(
            private_key.lms_tree_identifier,
            ((index - max_private_keys) as u32).to_be_bytes(),
            private_key.seed,
            private_key.lmots_parameter,
        );
        let lm_ots_public_key = lm_ots::keygen::generate_public_key(&lms_ots_private_key);

        hasher
            .chain(&D_LEAF)
            .chain(lm_ots_public_key.key.as_slice())
            .finalize()
    } else {
        let left = get_tree_element(2 * index, private_key, aux_data);
        let right = get_tree_element(2 * index + 1, private_key, aux_data);

        hasher
            .chain(&D_INTR)
            .chain(left.as_slice())
            .chain(right.as_slice())
            .finalize()
    };

    if let Some(expanded_aux_data) = aux_data.as_mut() {
        hss_save_aux_data::<H>(expanded_aux_data, index, result.as_slice());
    }

    result
}
