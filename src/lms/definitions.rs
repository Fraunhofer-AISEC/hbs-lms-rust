use core::marker::PhantomData;

use crate::constants::{MAX_M, MAX_PRIVATE_KEY_LENGTH};
use crate::hasher::sha256::Sha256Hasher;
use crate::hasher::Hasher;
use crate::lm_ots;
use crate::lm_ots::definitions::LmotsPrivateKey;
use crate::lm_ots::definitions::{IType, Seed};
use crate::lm_ots::parameter::LmotsParameter;
use crate::util::dynamic_array::DynamicArray;
use crate::util::helper::read_and_advance;
use crate::util::ustr::str32u;
use crate::util::ustr::u32str;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LmsAlgorithmType {
    LmsReserved = 0,
    LmsSha256M32H5 = 5,
    LmsSha256M32H10 = 6,
    LmsSha256M32H15 = 7,
    LmsSha256M32H20 = 8,
    LmsSha256M32H25 = 9,
}

impl LmsAlgorithmType {
    pub fn from_u32(x: u32) -> Option<LmsAlgorithmType> {
        match x {
            0 => Some(LmsAlgorithmType::LmsReserved),
            5 => Some(LmsAlgorithmType::LmsSha256M32H5),
            6 => Some(LmsAlgorithmType::LmsSha256M32H10),
            7 => Some(LmsAlgorithmType::LmsSha256M32H15),
            8 => Some(LmsAlgorithmType::LmsSha256M32H20),
            9 => Some(LmsAlgorithmType::LmsSha256M32H25),
            _ => None,
        }
    }
}

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub struct LmsAlgorithmParameter {
    pub h: u8,
    pub m: u8,
    pub _type: LmsAlgorithmType,
}

impl LmsAlgorithmParameter {
    pub fn new(_type: LmsAlgorithmType) -> Self {
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

    pub fn get_hasher(&self) -> impl Hasher {
        match self._type {
            LmsAlgorithmType::LmsReserved => panic!("Reserved parameter."),
            LmsAlgorithmType::LmsSha256M32H5 => Sha256Hasher::new(),
            LmsAlgorithmType::LmsSha256M32H10 => Sha256Hasher::new(),
            LmsAlgorithmType::LmsSha256M32H15 => Sha256Hasher::new(),
            LmsAlgorithmType::LmsSha256M32H20 => Sha256Hasher::new(),
            LmsAlgorithmType::LmsSha256M32H25 => Sha256Hasher::new(),
        }
    }

    pub fn number_of_lm_ots_keys(&self) -> usize {
        2usize.pow(self.h as u32)
    }

    pub fn get_binary_identifier(&self) -> u32 {
        self._type as u32
    }
}

#[allow(non_snake_case)]
#[derive(Debug, Clone, Copy)]
pub struct LmsPrivateKey<P: LmotsParameter> {
    pub lms_parameter: LmsAlgorithmParameter,
    pub I: IType,
    pub q: u32,
    pub seed: Seed,
    lmots_parameter: PhantomData<P>,
}

impl<P: LmotsParameter> PartialEq for LmsPrivateKey<P> {
    fn eq(&self, other: &Self) -> bool {
        self.lms_parameter == other.lms_parameter
            && self.I == other.I
            && self.q == other.q
            && self.seed == other.seed
            && self.lmots_parameter == other.lmots_parameter
    }
}

impl<P: LmotsParameter> Eq for LmsPrivateKey<P> {}

#[allow(non_snake_case)]
impl<P: LmotsParameter> LmsPrivateKey<P> {
    pub fn new(lms_parameter: LmsAlgorithmParameter, seed: Seed, I: IType) -> Self {
        LmsPrivateKey {
            lms_parameter,
            seed,
            I,
            q: 0,
            lmots_parameter: PhantomData,
        }
    }

    pub fn use_lmots_private_key(&mut self) -> Result<LmotsPrivateKey<P>, &'static str> {
        if self.q as usize >= self.lms_parameter.number_of_lm_ots_keys() {
            return Err("All private keys already used.");
        }
        self.q += 1;
        let key = lm_ots::generate_private_key(u32str(self.q - 1), self.I, self.seed);
        Ok(key)
    }

    pub fn to_binary_representation(&self) -> DynamicArray<u8, MAX_PRIVATE_KEY_LENGTH> {
        let mut result = DynamicArray::new();

        let lm_ots_parameter = <P>::new();

        result.append(&u32str(self.lms_parameter._type as u32));
        result.append(&u32str(lm_ots_parameter.get_type()));

        result.append(&self.I);
        result.append(&u32str(self.q));
        result.append(&self.seed);

        result
    }

    pub fn from_binary_representation(data: &[u8]) -> Option<Self> {
        let mut consumed_data = data;

        let lms_type = str32u(&consumed_data[..4]);
        consumed_data = &consumed_data[4..];

        let lms_parameter = match LmsAlgorithmType::from_u32(lms_type) {
            None => return None,
            Some(x) => LmsAlgorithmParameter::new(x),
        };

        let lm_ots_type = str32u(&consumed_data[..4]);
        consumed_data = &consumed_data[4..];

        let lm_ots_parameter = <P>::new();

        if !lm_ots_parameter.is_type_correct(lm_ots_type) {
            return None;
        }

        let mut initial: IType = [0u8; 16];
        initial.copy_from_slice(&consumed_data[..16]);
        consumed_data = &consumed_data[16..];

        let q = str32u(&consumed_data[..4]);
        consumed_data = &consumed_data[4..];

        let mut seed: Seed = [0u8; 32];
        seed.copy_from_slice(&consumed_data[..32]);
        // consumed_data = &consumed_data[32..];

        let key = LmsPrivateKey {
            lms_parameter,
            seed,
            I: initial,
            q,
            lmots_parameter: PhantomData,
        };

        Some(key)
    }
}

#[allow(non_snake_case)]
#[derive(Debug)]
pub struct LmsPublicKey<P: LmotsParameter> {
    pub lms_parameter: LmsAlgorithmParameter,
    pub key: DynamicArray<u8, MAX_M>,
    pub I: IType,
    lmots_parameter: PhantomData<P>,
}

impl<P: LmotsParameter> PartialEq for LmsPublicKey<P> {
    fn eq(&self, other: &Self) -> bool {
        self.lms_parameter == other.lms_parameter
            && self.key == other.key
            && self.I == other.I
            && self.lmots_parameter == other.lmots_parameter
    }
}

impl<P: LmotsParameter> Eq for LmsPublicKey<P> {}

#[allow(non_snake_case)]
impl<P: LmotsParameter> LmsPublicKey<P> {
    pub fn new(
        public_key: DynamicArray<u8, MAX_M>,
        lms_parameter: LmsAlgorithmParameter,
        I: IType,
    ) -> Self {
        LmsPublicKey {
            lms_parameter,
            key: public_key,
            I,
            lmots_parameter: PhantomData,
        }
    }

    pub fn to_binary_representation(&self) -> DynamicArray<u8, { 4 + 4 + 16 + MAX_M }> {
        let mut result = DynamicArray::new();

        let lm_ots_parameter = <P>::new();

        result.append(&u32str(self.lms_parameter.get_binary_identifier()));
        result.append(&u32str(lm_ots_parameter.get_type()));

        result.append(&self.I);
        result.append(&self.key.get_slice());

        result
    }

    pub fn from_binary_representation(data: &[u8]) -> Option<Self> {
        // Parsing like desribed in 5.4.2
        if data.len() < 8 {
            return None;
        }

        let mut data_index = 0;

        let pubtype = str32u(read_and_advance(data, 4, &mut data_index));

        let lms_parameter = match LmsAlgorithmType::from_u32(pubtype) {
            None => return None,
            Some(x) => LmsAlgorithmParameter::new(x),
        };

        let lm_ots_typecode = str32u(read_and_advance(data, 4, &mut data_index));

        let lm_ots_parameter = <P>::new();

        if !lm_ots_parameter.is_type_correct(lm_ots_typecode) {
            return None;
        }

        if data.len() - data_index == 24 + lms_parameter.m as usize {
            return None;
        }

        let mut initial: IType = [0u8; 16];
        initial.clone_from_slice(read_and_advance(data, 16, &mut data_index));

        let mut key: DynamicArray<u8, MAX_M> = DynamicArray::new();

        key.append(&data[data_index..data_index + lms_parameter.m as usize]);

        let public_key = LmsPublicKey {
            lms_parameter,
            I: initial,
            key,
            lmots_parameter: PhantomData,
        };

        Some(public_key)
    }
}

#[cfg(test)]
mod tests {
    use crate::{
        lm_ots::parameter,
        lms::{
            definitions::LmsAlgorithmParameter,
            keygen::{generate_private_key, generate_public_key},
        },
    };

    use super::{LmsPrivateKey, LmsPublicKey};

    #[test]
    fn test_private_key_binary_representation() {
        let lms_type = LmsAlgorithmParameter::new(crate::LmsAlgorithmType::LmsSha256M32H5);

        let private_key = generate_private_key::<parameter::LmotsSha256N32W2>(lms_type);

        let serialized = private_key.to_binary_representation();
        let deserialized =
            LmsPrivateKey::from_binary_representation(&serialized.get_slice()).unwrap();

        assert!(private_key == deserialized);
    }

    #[test]
    fn test_public_key_binary_representation() {
        let lms_type = LmsAlgorithmParameter::new(crate::LmsAlgorithmType::LmsSha256M32H5);

        let private_key = generate_private_key::<parameter::LmotsSha256N32W2>(lms_type);

        let public_key = generate_public_key(&private_key);

        let serialized = public_key.to_binary_representation();
        let deserialized = LmsPublicKey::from_binary_representation(serialized.get_slice())
            .expect("Deserialization must succeed.");

        assert!(public_key == deserialized);
    }
}
