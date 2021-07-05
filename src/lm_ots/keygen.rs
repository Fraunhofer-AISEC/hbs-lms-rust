use super::definitions::*;
use super::parameter::LmotsParameter;
use crate::constants::*;
use crate::util::dynamic_array::DynamicArray;
use crate::{
    constants::{D_PBLC, MAX_N, MAX_P},
    util::ustr::*,
};

pub fn generate_private_key<OTS: LmotsParameter>(
    i: IType,
    q: QType,
    seed: Seed,
) -> LmotsPrivateKey<OTS> {
    let mut key = DynamicArray::new();

    let mut hasher = <OTS>::get_hasher();

    for index in 0..<OTS>::get_p() {
        hasher.update(&i);
        hasher.update(&q);
        hasher.update(&u16str(index as u16));
        hasher.update(&[0xff]);
        hasher.update(&seed);

        key.push(hasher.finalize_reset());
    }

    LmotsPrivateKey::new(i, q, key)
}

pub fn generate_public_key<OTS: LmotsParameter>(
    private_key: &LmotsPrivateKey<OTS>,
) -> LmotsPublicKey<OTS> {
    let mut hasher = <OTS>::get_hasher();

    let max_word_index: usize = (1 << <OTS>::W) - 1;
    let key = &private_key.key;

    let mut y: DynamicArray<DynamicArray<u8, MAX_N>, MAX_P> = DynamicArray::new();

    for i in 0..<OTS>::get_p() as usize {
        let mut tmp = key[i].clone();

        for j in 0..max_word_index {
            hasher.update(&private_key.I);
            hasher.update(&private_key.q);
            hasher.update(&u16str(i as u16));
            hasher.update(&u8str(j as u8));
            hasher.update(tmp.get_slice());

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
        hasher.update(item.get_slice());
    }

    let mut public_key = DynamicArray::new();
    for value in hasher.finalize().into_iter() {
        public_key.push(value);
    }

    LmotsPublicKey::new(private_key.I, private_key.q, public_key)
}
