use crate::lm_ots::definitions::IType;
use crate::lm_ots::definitions::LmotsAlgorithmType;
use crate::lm_ots::definitions::LmotsPrivateKey;
use crate::util::hash::Hasher;
use crate::util::hash::Sha256Hasher;
use crate::util::helper::insert;
use crate::util::ustr::u32str;

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum LmsAlgorithmType {
    LmsReserved = 0,
    LmsSha256M32H5 = 5,
    LmsSha256M32H10 = 6,
    LmsSha256M32H15 = 7,
    LmsSha256M32H20 = 8,
    LmsSha256M32H25 = 9,
}

impl LmsAlgorithmType {
    pub fn get_parameter(self) -> LmsAlgorithmParameter {
        LmsAlgorithmParameter::get(self)
    }
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
            LmsAlgorithmType::LmsSha256M32H5 => {
                LmsAlgorithmParameter::internal_get(5, 32, LmsAlgorithmType::LmsSha256M32H5)
            }
            LmsAlgorithmType::LmsSha256M32H10 => {
                LmsAlgorithmParameter::internal_get(10, 32, LmsAlgorithmType::LmsSha256M32H10)
            }
            LmsAlgorithmType::LmsSha256M32H15 => {
                LmsAlgorithmParameter::internal_get(15, 32, LmsAlgorithmType::LmsSha256M32H15)
            }
            LmsAlgorithmType::LmsSha256M32H20 => {
                LmsAlgorithmParameter::internal_get(20, 32, LmsAlgorithmType::LmsSha256M32H20)
            }
            LmsAlgorithmType::LmsSha256M32H25 => {
                LmsAlgorithmParameter::internal_get(25, 32, LmsAlgorithmType::LmsSha256M32H25)
            }
        }
    }

    fn internal_get(h: u8, m: u8, _type: LmsAlgorithmType) -> Self {
        LmsAlgorithmParameter { h, m, _type }
    }

    pub fn get_hasher(&self) -> Box<dyn Hasher> {
        match self._type {
            LmsAlgorithmType::LmsReserved => panic!("Reserved parameter."),
            LmsAlgorithmType::LmsSha256M32H5 => Box::new(Sha256Hasher::new()),
            LmsAlgorithmType::LmsSha256M32H10 => Box::new(Sha256Hasher::new()),
            LmsAlgorithmType::LmsSha256M32H15 => Box::new(Sha256Hasher::new()),
            LmsAlgorithmType::LmsSha256M32H20 => Box::new(Sha256Hasher::new()),
            LmsAlgorithmType::LmsSha256M32H25 => Box::new(Sha256Hasher::new()),
        }
    }
}

#[allow(non_snake_case)]
pub struct LmsPrivateKey {
    pub lms_type: LmsAlgorithmType,
    pub lm_ots_type: LmotsAlgorithmType,
    pub key: Vec<LmotsPrivateKey>,
    pub I: IType,
    pub q: u32,
}

#[allow(non_snake_case)]
impl LmsPrivateKey {
    pub fn new(
        lms_type: LmsAlgorithmType,
        lmots_type: LmotsAlgorithmType,
        key: Vec<LmotsPrivateKey>,
        I: IType,
    ) -> Self {
        LmsPrivateKey {
            lms_type,
            lm_ots_type: lmots_type,
            key,
            I,
            q: 0,
        }
    }

    pub fn use_lmots_private_key(&mut self) -> Result<&LmotsPrivateKey, &'static str> {
        if self.q as usize > self.key.len() {
            return Err("All private keys already used.");
        }
        self.q += 1;
        Ok(&self.key[self.q as usize - 1])
    }

    pub fn to_binary_representation(&self) -> Vec<u8> {
        let mut result = Vec::new();

        insert(&u32str(self.lms_type as u32), &mut result);
        insert(&u32str(self.lm_ots_type as u32), &mut result);
        insert(&self.I, &mut result);
        insert(&u32str(self.q), &mut result);

        let keys = self
            .key
            .iter()
            .map(|key| key.get_flat_key())
            .flatten()
            .collect::<Vec<u8>>();

        insert(&keys, &mut result);

        result
    }
}

#[allow(non_snake_case)]
pub struct LmsPublicKey {
    pub lm_ots_type: LmotsAlgorithmType,
    pub lms_type: LmsAlgorithmType,
    pub key: Vec<u8>,
    pub tree: Vec<Vec<u8>>,
    pub I: IType,
}

#[allow(non_snake_case)]
impl LmsPublicKey {
    pub fn new(
        public_key: Vec<u8>,
        tree: Vec<Vec<u8>>,
        lm_ots_type: LmotsAlgorithmType,
        lms_type: LmsAlgorithmType,
        I: IType,
    ) -> Self {
        LmsPublicKey {
            lm_ots_type,
            lms_type,
            key: public_key,
            tree,
            I,
        }
    }

    pub fn to_binary_representation(&self) -> Vec<u8> {
        let mut result = Vec::new();

        insert(&u32str(self.lms_type as u32), &mut result);
        insert(&u32str(self.lm_ots_type as u32), &mut result);
        insert(&self.I, &mut result);
        insert(&self.tree[1], &mut result);

        result
    }
}
