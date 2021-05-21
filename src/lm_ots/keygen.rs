use super::definitions::*;
use crate::{definitions::D_PBLC, util::ustr::*, util::random::*};


pub fn GeneratePrivateKey(I: I_Type, q: q_Type, _type: lmots_algorithm_type) -> LmotsPrivateKey {
    let parameter = lmots_algorithm_parameter::get(_type);
    let mut key = vec![vec![0u8; parameter.n as usize]; parameter.p as usize];

    for item in key.iter_mut() {
        get_random(item);
    }

    LmotsPrivateKey::new(I, q, parameter, key)
}

pub fn GeneratePublicKey(private_key: &LmotsPrivateKey) -> LmotsPublicKey {
    let parameter = &private_key.parameter;

    let max_word_index: usize = (1 << parameter.w) - 1;
    let key = &private_key.key;

    let mut hasher = parameter.get_hasher();

    let mut y = vec![vec![0_u8; parameter.n as usize]; parameter.p as usize];    

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

    let mut K = vec![0u8; parameter.n as usize];
    for (index, value) in hasher.finalize().iter().enumerate() {
        K[index] = *value;
    }

    LmotsPublicKey::new(private_key.I, private_key.q, *parameter, K)
}