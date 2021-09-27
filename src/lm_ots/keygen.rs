use super::definitions::*;
use super::parameters::LmotsParameter;
use crate::constants::*;
use crate::hasher::Hasher;
use crate::util::dynamic_array::DynamicArray;
use crate::{
    constants::{D_PBLC, MAX_HASH, MAX_P},
    util::ustr::*,
};

pub fn generate_private_key<H: Hasher>(
    i: LmsTreeIdentifier,
    q: LmsLeafIdentifier,
    seed: Seed,
    lmots_parameter: LmotsParameter<H>,
) -> LmotsPrivateKey<H> {
    let mut key = DynamicArray::new();

    let mut hasher = lmots_parameter.get_hasher();

    for index in 0..lmots_parameter.get_p() {
        hasher.update(&i);
        hasher.update(&q);
        hasher.update(&u16str(index as u16));
        hasher.update(&[0xff]);
        hasher.update(&seed);

        key.push(hasher.finalize_reset());
    }

    LmotsPrivateKey::new(i, q, key, lmots_parameter)
}

pub fn generate_public_key<H: Hasher>(private_key: &LmotsPrivateKey<H>) -> LmotsPublicKey<H> {
    let lmots_parameter = &private_key.lmots_parameter;
    let mut hasher = lmots_parameter.get_hasher();

    let hash_chain_iterations: usize = 2_usize.pow(lmots_parameter.get_winternitz() as u32) - 1;
    let key = &private_key.key;

    let mut signature_data: DynamicArray<DynamicArray<u8, MAX_HASH>, MAX_P> = DynamicArray::new();

    for i in 0..lmots_parameter.get_p() as usize {
        let mut hash_chain_data = H::prepare_hash_chain_data(&private_key.lms_tree_identifier, &private_key.lms_leaf_identifier);
        let result = hasher.do_hash_chain(&mut hash_chain_data, i as u16, key[i].as_slice(), 0, hash_chain_iterations);

        signature_data.push(result);
    }

    hasher.update(&private_key.lms_tree_identifier);
    hasher.update(&private_key.lms_leaf_identifier);
    hasher.update(&D_PBLC);

    for item in signature_data.into_iter() {
        hasher.update(item.as_slice());
    }

    let mut public_key = DynamicArray::new();
    for value in hasher.finalize().into_iter() {
        public_key.push(value);
    }

    LmotsPublicKey::new(
        private_key.lms_tree_identifier,
        private_key.lms_leaf_identifier,
        public_key,
        *lmots_parameter,
    )
}
