use super::helper::get_tree_element;
use crate::lm_ots::definitions::IType;
use crate::lm_ots::definitions::LmotsAlgorithmType;
use crate::lm_ots::definitions::Seed;
use crate::lms::definitions::LmsAlgorithmType;
use crate::lms::definitions::LmsPrivateKey;
use crate::lms::definitions::LmsPublicKey;

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

pub fn generate_public_key(private_key: &LmsPrivateKey) -> LmsPublicKey {
    let public_key = get_tree_element(1, private_key);

    LmsPublicKey::new(
        public_key,
        private_key.lm_ots_type,
        private_key.lms_type,
        private_key.I,
    )
}
