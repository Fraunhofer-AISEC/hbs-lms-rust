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
    q: QType,
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

    let max_word_index: usize = (1 << lmots_parameter.get_winternitz()) - 1;
    let key = &private_key.key;

    let mut y: DynamicArray<DynamicArray<u8, MAX_HASH>, MAX_P> = DynamicArray::new();

    for i in 0..lmots_parameter.get_p() as usize {
        let mut tmp = key[i].clone();

        for j in 0..max_word_index {
            hasher.update(&private_key.I);
            hasher.update(&private_key.q);
            hasher.update(&u16str(i as u16));
            hasher.update(&u8str(j as u8));
            hasher.update(tmp.as_slice());

            for (index, value) in hasher.finalize_reset().into_iter().enumerate() {
                tmp[index] = value;
            }
        }

        y.push(tmp);
    }

    hasher.update(&private_key.I);
    hasher.update(&private_key.q);
    hasher.update(&D_PBLC);

    for item in y.into_iter() {
        hasher.update(item.as_slice());
    }

    let mut public_key = DynamicArray::new();
    for value in hasher.finalize().into_iter() {
        public_key.push(value);
    }

    LmotsPublicKey::new(private_key.I, private_key.q, public_key, *lmots_parameter)
}
