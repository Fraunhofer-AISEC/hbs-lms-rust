use std::usize;

use crate::{
    definitions::D_MESG,
    util::{
        coef::coef,
        helper::insert,
        random::get_random,
        ustr::{str32u, u16str, u32str, u8str},
    },
    LmotsAlgorithmType,
};

use super::definitions::{LmotsAlgorithmParameter, LmotsPrivateKey};

#[allow(non_snake_case)]
pub struct LmotsSignature {
    pub parameter: LmotsAlgorithmParameter,
    pub C: Vec<u8>,
    pub y: Vec<Vec<u8>>,
}

impl LmotsSignature {
    #[allow(non_snake_case)]
    pub fn sign(private_key: &LmotsPrivateKey, message: &[u8]) -> Self {
        let mut C = vec![0u8; private_key.parameter.n as usize];
        get_random(C.as_mut_slice());

        let mut hasher = private_key.parameter.get_hasher();

        hasher.update(&private_key.I);
        hasher.update(&private_key.q);
        hasher.update(&D_MESG);
        hasher.update(C.as_mut_slice());
        hasher.update(message);

        let Q = hasher.finalize_reset();
        let Q_checksum = private_key.parameter.checksum(Q.as_slice());

        let mut Q_and_checksum = Q;
        Q_and_checksum.push((Q_checksum >> 8 & 0xff) as u8);
        Q_and_checksum.push((Q_checksum & 0xff) as u8);

        let mut y =
            vec![vec![0u8; private_key.parameter.n as usize]; private_key.parameter.p as usize];

        for i in 0..private_key.parameter.p {
            let a = coef(
                &Q_and_checksum.as_slice(),
                i as u64,
                private_key.parameter.w as u64,
            );
            let mut tmp = private_key.key[i as usize].clone();
            for j in 0..a {
                hasher.update(&private_key.I);
                hasher.update(&private_key.q);
                hasher.update(&u16str(i));
                hasher.update(&u8str(j as u8));
                hasher.update(&tmp);
                tmp = hasher.finalize_reset();
            }
            y[i as usize] = tmp;
        }

        LmotsSignature {
            parameter: private_key.parameter,
            C,
            y,
        }
    }

    pub fn to_binary_representation(&self) -> Vec<u8> {
        let mut result = Vec::new();

        insert(&u32str(self.parameter._type as u32), &mut result);
        insert(&self.C, &mut result);

        let keys = self.y.iter().flatten().cloned().collect::<Vec<_>>();

        insert(&keys, &mut result);

        result
    }

    #[allow(non_snake_case)]
    pub fn from_binary_representation(data: &[u8]) -> Option<Self> {
        if data.len() < 4 {
            return None;
        }

        let mut consumed_data = data;

        let lm_ots_type = str32u(&consumed_data[..4]);
        consumed_data = &consumed_data[4..];

        let lm_ots_type = match LmotsAlgorithmType::from_u32(lm_ots_type) {
            None => return None,
            Some(x) => x,
        };

        let lm_ots_parameter = lm_ots_type.get_parameter();

        if data.len() != 4 + lm_ots_parameter.n as usize * (lm_ots_parameter.p as usize + 1) {
            return None;
        }

        let C = consumed_data[..lm_ots_parameter.n as usize].to_vec();
        consumed_data = &consumed_data[lm_ots_parameter.n as usize..];

        let mut y: Vec<Vec<u8>> = Vec::new();

        for _ in 0..lm_ots_parameter.p {
            let temp = consumed_data[..lm_ots_parameter.n as usize].to_vec();
            y.push(temp);

            consumed_data = &consumed_data[lm_ots_parameter.n as usize..];
        }

        let signature = Self {
            parameter: lm_ots_parameter,
            C,
            y,
        };

        Some(signature)
    }
}
