use crate::lms::definitions::LmsPrivateKey;
use crate::lms::definitions::LmsAlgorithmType;
use crate::lms::definitions::LmsAlgorithmParameter;
use crate::lm_ots::definitions::LmotsPrivateKey;
use crate::util::ustr::u32str;
use crate::lm_ots::definitions::LmotsAlgorithmType;
use crate::lm_ots::definitions::IType;

pub fn generate_private_key(lms_type: LmsAlgorithmType, lmots_type: LmotsAlgorithmType) -> LmsPrivateKey {
    let parameters = LmsAlgorithmParameter::get(lms_type);

    let mut i: IType = [0u8; 16];
    crate::util::random::get_random(&mut i);

    let max_private_keys = 2_u32.pow(parameters.h.into());

    let mut private_keys: Vec<LmotsPrivateKey> = Vec::new();

    for q in 0..max_private_keys {
        let q_type = u32str(q);
        let new_lmots_private_key = crate::lm_ots::generate_private_key(q_type, i, lmots_type);
        private_keys.push(new_lmots_private_key);
    }

    LmsPrivateKey::new(lms_type, lmots_type, private_keys)
}
