use crate::lms::definitions::LmsPublicKey;
use crate::definitions::D_INTR;
use crate::definitions::D_LEAF;
use crate::lms::definitions::LmsPrivateKey;
use crate::lms::definitions::LmsAlgorithmType;
use crate::lm_ots::definitions::LmotsPrivateKey;
use crate::util::ustr::u32str;
use crate::lm_ots::definitions::LmotsAlgorithmType;
use crate::lm_ots::definitions::IType;

pub fn generate_private_key(lms_type: LmsAlgorithmType, lmots_type: LmotsAlgorithmType) -> LmsPrivateKey {
    let parameters = lms_type.get_parameter();

    let mut i: IType = [0u8; 16];
    crate::util::random::get_random(&mut i);

    let max_private_keys = 2_u32.pow(parameters.h.into());

    let mut private_keys: Vec<LmotsPrivateKey> = Vec::new();

    for q in 0..max_private_keys {
        let q_type = u32str(q);
        let new_lmots_private_key = crate::lm_ots::generate_private_key(q_type, i, lmots_type);
        private_keys.push(new_lmots_private_key);
    }

    LmsPrivateKey::new(lms_type, lmots_type, private_keys, i)
}


pub fn generate_public_key(lms_type: LmsAlgorithmType, private_key: &LmsPrivateKey) -> LmsPublicKey {
    let lms_parameter = lms_type.get_parameter();
    let num_lmots_keys = private_key.key.len();

    let max_private_keys = 2_usize.pow(lms_parameter.h.into());

    let mut hasher = lms_parameter.get_hasher();

    let mut hash_stack: Vec<Vec<u8>> = Vec::new();

    for i in 0..max_private_keys {
        let mut r = i + num_lmots_keys;
        hasher.update(&private_key.i);
        hasher.update(&u32str(r as u32));
        hasher.update(&D_LEAF);
        
        let lm_ots_public_key = crate::lm_ots::generate_public_key(&private_key.key[i]);
        hasher.update(&lm_ots_public_key.key);

        let mut temp = hasher.finalize_reset();
        let mut j = i;

        while j % 2 == 1 {
            r = (r - 1) / 2;
            j = (j - 1) / 2;

            let left_side = hash_stack.pop().expect("Stack should have a value.");

            hasher.update(&private_key.i);
            hasher.update(&u32str(r as u32));
            hasher.update(&D_INTR);
            hasher.update(&left_side);
            hasher.update(&temp);

            temp = hasher.finalize_reset();
        }
        hash_stack.push(temp);
    }

    let public_key = hash_stack.pop().expect("Stack should have a value.");

    LmsPublicKey::new(public_key)
}