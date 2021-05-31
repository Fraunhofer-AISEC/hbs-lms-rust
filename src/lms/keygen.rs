use crate::definitions::D_INTR;
use crate::definitions::D_LEAF;
use crate::lm_ots::definitions::IType;
use crate::lm_ots::definitions::LmotsAlgorithmType;
use crate::lm_ots::definitions::LmotsPrivateKey;
use crate::lms::definitions::LmsAlgorithmType;
use crate::lms::definitions::LmsPrivateKey;
use crate::lms::definitions::LmsPublicKey;
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

    let mut private_keys: Vec<LmotsPrivateKey> = Vec::new();

    for q in 0..max_private_keys {
        let q = u32str(q);
        let new_lmots_private_key = crate::lm_ots::generate_private_key(q, i, lmots_type);
        private_keys.push(new_lmots_private_key);
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

    let mut hash_tree: Vec<Vec<u8>> =
        vec![vec![0u8; lms_parameter.m as usize]; 2_usize.pow((lms_parameter.h + 1).into())]; // Use index + 1 to start accessing at 1

    let mut hash_stack: Vec<Vec<u8>> = Vec::new();

    for i in 0..max_private_keys {
        let mut r = i + num_lmots_keys;
        hasher.update(&private_key.I);
        hasher.update(&u32str(r as u32));
        hasher.update(&D_LEAF);

        let lm_ots_public_key = crate::lm_ots::generate_public_key(&private_key.key[i]);
        hasher.update(&lm_ots_public_key.key);

        let mut temp = hasher.finalize_reset();

        hash_tree[r] = temp.clone();

        let mut j = i;

        while j % 2 == 1 {
            r = (r - 1) / 2;
            j = (j - 1) / 2;

            let left_side = hash_stack.pop().expect("Stack should have a value.");

            hasher.update(&private_key.I);
            hasher.update(&u32str(r as u32));
            hasher.update(&D_INTR);
            hasher.update(&left_side);
            hasher.update(&temp);

            temp = hasher.finalize_reset();
            hash_tree[r] = temp.clone();
        }
        hash_stack.push(temp);
    }
    let public_key = hash_stack.pop().expect("Stack should have a value.");

    LmsPublicKey::new(
        public_key,
        hash_tree,
        private_key.lmots_type,
        private_key.lms_type,
        private_key.I,
    )
}

#[cfg(test)]
mod tests {
    use crate::lm_ots::definitions::LmotsAlgorithmType;
    use crate::lms::definitions::LmsAlgorithmType;
    use crate::lms::keygen::*;

    #[test]
    fn test_key_generation() {
        let private = generate_private_key(
            LmsAlgorithmType::LmsSha256M32H5,
            LmotsAlgorithmType::LmotsSha256N32W1,
        );
        let public = generate_public_key(&private);
    }
}
