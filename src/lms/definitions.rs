use crate::lm_ots::definitions::LmotsAlgorithmType;
use crate::lm_ots::definitions::LmotsPrivateKey;

#[derive(Clone, Copy)]
pub enum LmsAlgorithmType {
    LmsReserved = 0,
    LmsSha256M32H5 = 5,
    LmsSha256M32H10 = 6,
    LmsSha256M32H15 = 7,
    LmsSha256M32H20 = 8,
    LmsSha256M32H25 = 9,
}

pub struct LmsAlgorithmParameter {
    pub h: u8,
    pub m: u8,
    pub _type: LmsAlgorithmType,
}

impl LmsAlgorithmParameter {
    pub fn get(_type: LmsAlgorithmType) -> Self {
        match _type {
            LmsAlgorithmType::LmsReserved => panic!("Reserved parameter."),
            LmsAlgorithmType::LmsSha256M32H5 => LmsAlgorithmParameter::internal_get(5, 32, LmsAlgorithmType::LmsSha256M32H5),
            LmsAlgorithmType::LmsSha256M32H10 => LmsAlgorithmParameter::internal_get(10, 32, LmsAlgorithmType::LmsSha256M32H10),
            LmsAlgorithmType::LmsSha256M32H15 => LmsAlgorithmParameter::internal_get(15, 32, LmsAlgorithmType::LmsSha256M32H15),
            LmsAlgorithmType::LmsSha256M32H20 => LmsAlgorithmParameter::internal_get(20, 32, LmsAlgorithmType::LmsSha256M32H20),
            LmsAlgorithmType::LmsSha256M32H25 => LmsAlgorithmParameter::internal_get(25, 32, LmsAlgorithmType::LmsSha256M32H25),

        }
    }

    fn internal_get(h: u8, m: u8, _type: LmsAlgorithmType) -> Self {
        LmsAlgorithmParameter { h, m, _type }
    }
}

pub struct LmsPrivateKey {
    pub lms_type: LmsAlgorithmType,
    pub lmots_type: LmotsAlgorithmType,
    pub key: Vec<LmotsPrivateKey>,
    pub q: usize,
}

impl LmsPrivateKey {
    pub fn new(lms_type: LmsAlgorithmType, lmots_type: LmotsAlgorithmType, key: Vec<LmotsPrivateKey>) -> Self {
        LmsPrivateKey {
            lms_type,
            lmots_type,
            key,
            q: 0
        }
    }

    pub fn use_lmots_private_key(&mut self) -> Result<&LmotsPrivateKey, &'static str> {
        if self.q > self.key.len() {
            return Err("All private keys already used.")
        }
        self.q += 1;
        Ok(&self.key[self.q - 1])
    }
}