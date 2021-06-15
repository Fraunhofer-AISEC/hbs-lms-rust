use crate::definitions::D_INTR;
use crate::definitions::D_LEAF;
use crate::definitions::MAX_LEAFS;
use crate::definitions::MAX_M;
use crate::definitions::MAX_TREE_ELEMENTS;
use crate::lm_ots::definitions::IType;
use crate::lm_ots::definitions::LmotsAlgorithmType;
use crate::lms::definitions::LmsAlgorithmType;
use crate::lms::definitions::LmsPrivateKey;
use crate::lms::definitions::LmsPublicKey;
use crate::util::hash::Hasher;
use crate::util::helper::is_power_of_two;
use crate::util::ustr::u32str;

pub fn generate_private_key(
    lms_type: LmsAlgorithmType,
    lmots_type: LmotsAlgorithmType,
) -> LmsPrivateKey {
    let parameters = lms_type.get_parameter();

    let mut i: IType = [0u8; 16];
    crate::util::random::get_random(&mut i);

    let max_private_keys = 2_u32.pow(parameters.h.into());

    let mut private_keys = [None; MAX_LEAFS];

    for q in 0..max_private_keys {
        let new_lmots_private_key = crate::lm_ots::generate_private_key(u32str(q), i, lmots_type);
        private_keys[q as usize] = Some(new_lmots_private_key);
    }

    LmsPrivateKey::new(lms_type, lmots_type, private_keys, i)
}

pub fn generate_public_key(private_key: &LmsPrivateKey) -> LmsPublicKey {
    let lms_parameter = private_key.lms_type.get_parameter();
    let num_lmots_keys = private_key.key.len();

    // num_lmots_keys must be a power of two
    assert!(is_power_of_two(num_lmots_keys));

    let max_private_keys = 2_usize.pow(lms_parameter.h.into());

    let mut hasher = lms_parameter.get_hasher();

    let mut hash_tree = [[0u8; MAX_M]; MAX_TREE_ELEMENTS + 1]; // Use index + 1 to start accessing at 1

    // TODO: CHECK THIS IMPL AGAIN

    for i in 0..max_private_keys {
        let mut r = i + num_lmots_keys;
        hasher.update(&private_key.I);
        hasher.update(&u32str(r as u32));
        hasher.update(&D_LEAF);

        let lm_ots_public_key = crate::lm_ots::generate_public_key(&private_key.key[i].unwrap());
        hasher.update(&lm_ots_public_key.key);

        let mut temp = hasher.finalize_reset();

        hash_tree[r] = temp;

        let mut j = i;

        while j % 2 == 1 {
            r = (r - 1) / 2;
            j = (j - 1) / 2;

            let left_side = hash_tree[j];

            hasher.update(&private_key.I);
            hasher.update(&u32str(r as u32));
            hasher.update(&D_INTR);
            hasher.update(&left_side);
            hasher.update(&temp);

            temp = hasher.finalize_reset();
            hash_tree[r] = temp;
        }
        // hash_tree[]
    }

    let public_key = hash_tree[1];

    LmsPublicKey::new(
        public_key,
        hash_tree,
        private_key.lm_ots_type,
        private_key.lms_type,
        private_key.I,
    )
}
