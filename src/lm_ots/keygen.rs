use super::definitions::*;
use super::parameters::LmotsParameter;
use crate::constants::*;
use crate::constants::{D_PBLC, MAX_HASH_SIZE, MAX_NUM_WINTERNITZ_CHAINS};
use crate::hasher::HashChain;
use crate::Seed;
use tinyvec::ArrayVec;

pub fn generate_private_key<H: HashChain>(
    lms_tree_identifier: LmsTreeIdentifier,
    lms_leaf_identifier: LmsLeafIdentifier,
    seed: Seed<H>,
    lmots_parameter: LmotsParameter<H>,
) -> LmotsPrivateKey<H> {
    let mut key = ArrayVec::new();

    let mut hasher = lmots_parameter.get_hasher();

    for index in 0..lmots_parameter.get_num_winternitz_chains() {
        hasher.update(&lms_tree_identifier);
        hasher.update(&lms_leaf_identifier);
        hasher.update(&index.to_be_bytes());
        hasher.update(&[0xff]);
        hasher.update(seed.as_slice());

        key.push(hasher.finalize_reset());
    }

    LmotsPrivateKey::new(
        lms_tree_identifier,
        lms_leaf_identifier,
        key,
        lmots_parameter,
    )
}

pub fn generate_public_key<H: HashChain>(private_key: &LmotsPrivateKey<H>) -> LmotsPublicKey<H> {
    let lmots_parameter = &private_key.lmots_parameter;
    let mut hasher = lmots_parameter.get_hasher();

    let num_winternitz_chains: usize = 2_usize.pow(lmots_parameter.get_winternitz() as u32) - 1;
    let key = &private_key.key;

    let mut public_key_data: ArrayVec<[ArrayVec<[u8; MAX_HASH_SIZE]>; MAX_NUM_WINTERNITZ_CHAINS]> =
        ArrayVec::new();

    for i in 0..lmots_parameter.get_num_winternitz_chains() as usize {
        let mut hash_chain_data = H::prepare_hash_chain_data(
            &private_key.lms_tree_identifier,
            &private_key.lms_leaf_identifier,
        );
        let result = hasher.do_hash_chain(
            &mut hash_chain_data,
            i as u16,
            key[i].as_slice(),
            0,
            num_winternitz_chains,
        );

        public_key_data.push(result);
    }

    hasher.update(&private_key.lms_tree_identifier);
    hasher.update(&private_key.lms_leaf_identifier);
    hasher.update(&D_PBLC);

    for item in public_key_data.into_iter() {
        hasher.update(item.as_slice());
    }

    let public_key = hasher.finalize();

    LmotsPublicKey::new(
        private_key.lms_tree_identifier,
        private_key.lms_leaf_identifier,
        public_key,
        *lmots_parameter,
    )
}
