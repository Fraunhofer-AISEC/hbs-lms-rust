use std::usize;

use crate::{definitions::D_MESG, util::{coef::coef, random::get_random, ustr::{u16str, u8str}}};

use super::definitions::{LmotsAlgorithmParameter, LmotsPrivateKey};

#[allow(non_snake_case)]
pub struct LmotsSignature {
    pub parameter: LmotsAlgorithmParameter,
    pub C: Vec<u8>,
    pub y: Vec<Vec<u8>>,
    pub message: Vec<u8>,
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

        let mut y = vec![vec![0u8; private_key.parameter.n as usize]; private_key.parameter.p as usize];

        for i in 0..private_key.parameter.p {
            let a = coef(&Q_and_checksum.as_slice(), i as u64, private_key.parameter.w as u64);
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
            message: message.to_vec(),
        }
    }
}