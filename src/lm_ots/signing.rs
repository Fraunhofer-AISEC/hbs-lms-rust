use crate::util::dynamic_array::DynamicArray;
use crate::util::hash::Hasher;
use crate::{
    definitions::{D_MESG, MAX_N, MAX_P},
    util::{
        coef::coef,
        random::get_random,
        ustr::{str32u, u16str, u32str, u8str},
    },
    LmotsAlgorithmType,
};
use core::usize;

use super::definitions::{LmotsAlgorithmParameter, LmotsPrivateKey};

#[allow(non_snake_case)]
pub struct LmotsSignature {
    pub parameter: LmotsAlgorithmParameter,
    pub C: [u8; MAX_N],
    pub y: [[u8; MAX_N]; MAX_P],
}

impl LmotsSignature {
    #[allow(non_snake_case)]
    pub fn sign(private_key: &LmotsPrivateKey, message: &[u8]) -> Self {
        let mut C = [0u8; MAX_N];
        get_random(&mut C);

        let mut hasher = private_key.parameter.get_hasher();

        hasher.update(&private_key.I);
        hasher.update(&private_key.q);
        hasher.update(&D_MESG);
        hasher.update(&C);
        hasher.update(message);

        let Q = hasher.finalize_reset();
        let Q_and_checksum = private_key.parameter.get_appended_with_checksum(&Q);

        let mut y = [[0u8; MAX_N]; MAX_P];

        for i in 0..private_key.parameter.p {
            let a = coef(&Q_and_checksum, i as u64, private_key.parameter.w as u64);
            let mut tmp = private_key.key[i as usize];
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

    pub fn to_binary_representation(&self) -> DynamicArray<u8, { 4 + MAX_N + (MAX_N * MAX_P) }> {
        let mut result = DynamicArray::new();

        result.append(&u32str(self.parameter._type as u32));
        result.append(&self.C);

        let keys = self.y.iter().flatten().cloned();

        for byte in keys {
            result.append(&[byte]);
        }

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

        let mut C = [0u8; MAX_N];

        C.copy_from_slice(&consumed_data[..lm_ots_parameter.n as usize]);
        consumed_data = &consumed_data[lm_ots_parameter.n as usize..];

        let mut y = [[0u8; MAX_N]; MAX_P];

        for i in 0..lm_ots_parameter.p {
            let mut temp = [0u8; MAX_N];
            temp.copy_from_slice(&consumed_data[..lm_ots_parameter.n as usize]);
            y[i as usize] = temp;

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
