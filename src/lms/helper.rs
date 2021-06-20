use crate::util::hash::Hasher;
use crate::{
    definitions::{D_INTR, D_LEAF, MAX_N, MAX_TREE_ELEMENTS},
    util::ustr::u32str,
};

use super::definitions::LmsPrivateKey;

pub fn get_tree_element(
    tree: &mut [Option<[u8; MAX_N]>; MAX_TREE_ELEMENTS + 1],
    r: usize,
    max_private_keys: usize,
    private_key: &LmsPrivateKey,
) -> [u8; MAX_N] {
    if let Some(x) = tree[r] {
        return x;
    }

    let mut hasher = private_key.lms_type.get_parameter().get_hasher();

    hasher.update(&private_key.I);
    hasher.update(&u32str(r as u32));

    if r >= max_private_keys {
        hasher.update(&D_LEAF);
        let lms_ots_private_key = crate::lm_ots::generate_private_key(
            u32str((r - max_private_keys) as u32),
            private_key.I,
            private_key.seed,
            private_key.lm_ots_type,
        );
        let lm_ots_public_key = crate::lm_ots::generate_public_key(&lms_ots_private_key);
        hasher.update(&lm_ots_public_key.key.get_slice());
    } else {
        hasher.update(&D_INTR);
        let left = get_tree_element(tree, 2 * r, max_private_keys, private_key);
        tree[2 * r] = Some(left);

        let right = get_tree_element(tree, 2 * r + 1, max_private_keys, private_key);
        tree[2 * r + 1] = Some(right);

        hasher.update(&tree[2 * r].unwrap());
        hasher.update(&tree[2 * r + 1].unwrap());
    }

    let temp = hasher.finalize();

    let mut arr = [0u8; 32];
    arr.copy_from_slice(&temp);

    tree[r] = Some(arr);

    tree[r].unwrap()
}
