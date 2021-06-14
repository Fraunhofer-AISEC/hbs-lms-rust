use super::definitions::*;
use crate::util::hash::Hasher;
use crate::{
    definitions::{D_PBLC, MAX_N, MAX_P},
    util::random::*,
    util::ustr::*,
};

pub fn generate_private_key(i: IType, q: QType, _type: LmotsAlgorithmType) -> LmotsPrivateKey {
    let parameter = _type.get_parameter();
    let mut key = [[0u8; MAX_N]; MAX_P];

    for item in key.iter_mut() {
        get_random(item);
    }

    LmotsPrivateKey::new(i, q, parameter, key)
}

pub fn generate_public_key(private_key: &LmotsPrivateKey) -> LmotsPublicKey {
    let parameter = &private_key.parameter;

    let max_word_index: usize = (1 << parameter.w) - 1;
    let key = &private_key.key;

    let mut hasher = parameter.get_hasher();

    let mut y = [[0u8; MAX_N]; MAX_P];

    for i in 0..parameter.p as usize {
        let mut tmp = key[i].clone();

        for j in 0..max_word_index {
            hasher.update(&private_key.I);
            hasher.update(&private_key.q);
            hasher.update(&u16str(i as u16));
            hasher.update(&u8str(j as u8));
            hasher.update(&tmp);

            for (index, value) in hasher.finalize_reset().iter().enumerate() {
                tmp[index] = *value;
            }
        }

        y[i] = tmp;
    }

    hasher.update(&private_key.I);
    hasher.update(&private_key.q);
    hasher.update(&D_PBLC);

    for item in y.iter() {
        hasher.update(item);
    }

    let mut public_key = [0u8; MAX_N];
    for (index, value) in hasher.finalize().iter().enumerate() {
        public_key[index] = *value;
    }

    LmotsPublicKey::new(private_key.I, private_key.q, *parameter, public_key)
}
