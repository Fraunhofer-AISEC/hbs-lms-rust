use super::definitions::*;
use crate::{definitions::D_PBLC, util::ustr::*, util::random::*};

pub fn generate_private_key(i: IType, q: QType, _type: LmotsAlgorithmType) -> LmotsPrivateKey {
    let parameter = LmotsAlgorithmParameter::get(_type);
    let mut key = vec![vec![0u8; parameter.n as usize]; parameter.p as usize];

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

    let mut y = vec![vec![0_u8; parameter.n as usize]; parameter.p as usize];    

    for i in 0..parameter.p as usize {
        let mut tmp = key[i].clone();
    
        for j in 0..max_word_index {
            hasher.update(&private_key.i);
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

    hasher.update(&private_key.i);
    hasher.update(&private_key.q);
    hasher.update(&D_PBLC);

    for item in y.iter() {
        hasher.update(item);
    }

    let mut public_key = vec![0u8; parameter.n as usize];
    for (index, value) in hasher.finalize().iter().enumerate() {
        public_key[index] = *value;
    }

    LmotsPublicKey::new(private_key.i, private_key.q, *parameter, public_key)
}

#[cfg(test)]
mod tests {
    use crate::lm_ots::definitions::{IType, QType};

    use super::*;

    #[test]
    fn public_key_generation() {
        let i: IType = [2u8; 16];
        let q: QType = [2u8; 4];

        let private_key = generate_private_key(i, q, LmotsAlgorithmType::LmotsSha256N32W1);
        let public_key = generate_public_key(&private_key);
    }    
}