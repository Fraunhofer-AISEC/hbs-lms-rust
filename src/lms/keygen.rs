use crate::definitions::D_INTR;
use crate::definitions::D_LEAF;
use crate::definitions::MAX_M;
use crate::definitions::MAX_TREE_ELEMENTS;
use crate::lm_ots::definitions::IType;
use crate::lm_ots::definitions::LmotsAlgorithmType;
use crate::lm_ots::definitions::Seed;
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
    let mut i: IType = [0u8; 16];
    crate::util::random::get_random(&mut i);

    let mut seed: Seed = [0u8; 32];
    crate::util::random::get_random(&mut seed);

    LmsPrivateKey::new(lms_type, lmots_type, seed, i)
}

fn rec_fill(
    tree: &mut [Option<[u8; 32]>; MAX_TREE_ELEMENTS + 1],
    r: usize,
    max_private_keys: usize,
    private_key: &LmsPrivateKey,
) -> [u8; 32] {
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
        hasher.update(&lm_ots_public_key.key);

        let temp = hasher.finalize();

        let mut arr = [0u8; 32];
        arr.copy_from_slice(&temp);

        tree[r] = Some(arr);
        tree[r].unwrap()
    } else {
        hasher.update(&D_INTR);
        let left = rec_fill(tree, 2 * r, max_private_keys, private_key);
        tree[2 * r] = Some(left);

        let right = rec_fill(tree, 2 * r + 1, max_private_keys, private_key);
        tree[2 * r + 1] = Some(right);

        hasher.update(&tree[2 * r].unwrap());
        hasher.update(&tree[2 * r + 1].unwrap());

        let temp = hasher.finalize();

        let mut arr = [0u8; 32];
        arr.copy_from_slice(&temp);

        tree[r] = Some(arr);

        tree[r].unwrap()
    }
}

pub fn generate_public_key(private_key: &LmsPrivateKey) -> LmsPublicKey {
    let lms_parameter = private_key.lms_type.get_parameter();
    let num_lmots_keys = private_key.lms_type.get_parameter().number_of_lm_ots_keys();

    // num_lmots_keys must be a power of two
    assert!(is_power_of_two(num_lmots_keys));

    let max_private_keys = 2_usize.pow(lms_parameter.h.into());

    let mut temp_hash_tree: [Option<[u8; MAX_M]>; MAX_TREE_ELEMENTS + 1] =
        [None; MAX_TREE_ELEMENTS + 1]; // Use index + 1 to start accessing at 1

    let public_key = rec_fill(&mut temp_hash_tree, 1, max_private_keys, private_key);

    let mut hash_tree = [[0u8; 32]; 64];

    for (index, temp_hash) in temp_hash_tree.iter().enumerate() {
        hash_tree[index] = temp_hash.unwrap_or([0u8; 32]);
    }

    LmsPublicKey::new(
        public_key,
        hash_tree,
        private_key.lm_ots_type,
        private_key.lms_type,
        private_key.I,
    )
}
