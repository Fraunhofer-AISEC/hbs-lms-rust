use crate::constants::{MAX_M, MAX_PRIV_KEY_LENGTH};
use crate::lm_ots;
use crate::lm_ots::definitions::LmotsAlgorithmType;
use crate::lm_ots::definitions::LmotsPrivateKey;
use crate::lm_ots::definitions::{IType, Seed};
use crate::util::dynamic_array::DynamicArray;
use crate::util::hash::Hasher;
use crate::util::hash::Sha256Hasher;
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
    pub fn get_parameter(self) -> LmsAlgorithmParameter {
        LmsAlgorithmParameter::get(self)
    }

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

#[derive(Debug, PartialEq, Eq)]
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
}

#[allow(non_snake_case)]
#[derive(Debug, PartialEq, Eq)]
pub struct LmsPrivateKey {
    pub lms_type: LmsAlgorithmType,
    pub lm_ots_type: LmotsAlgorithmType,
    pub I: IType,
    pub q: u32,
    pub seed: Seed,
}

#[allow(non_snake_case)]
impl LmsPrivateKey {
    pub fn new(
        lms_type: LmsAlgorithmType,
        lmots_type: LmotsAlgorithmType,
        seed: Seed,
        I: IType,
    ) -> Self {
        LmsPrivateKey {
            lms_type,
            lm_ots_type: lmots_type,
            seed,
            I,
            q: 0,
        }
    }

    pub fn use_lmots_private_key(&mut self) -> Result<LmotsPrivateKey, &'static str> {
        if self.q as usize >= self.lms_type.get_parameter().number_of_lm_ots_keys() {
            return Err("All private keys already used.");
        }
        self.q += 1;
        let key =
            lm_ots::generate_private_key(u32str(self.q - 1), self.I, self.seed, self.lm_ots_type);
        Ok(key)
    }

    pub fn to_binary_representation(&self) -> DynamicArray<u8, MAX_PRIV_KEY_LENGTH> {
        let mut result = DynamicArray::new();

        result.append(&u32str(self.lms_type as u32));
        result.append(&u32str(self.lm_ots_type as u32));

        result.append(&self.I);
        result.append(&u32str(self.q));
        result.append(&self.seed);

        result
    }

    pub fn from_binary_representation(data: &[u8]) -> Option<Self> {
        let mut consumed_data = data;

        let lms_type = str32u(&consumed_data[..4]);
        consumed_data = &consumed_data[4..];

        let lms_type = match LmsAlgorithmType::from_u32(lms_type) {
            None => return None,
            Some(x) => x,
        };

        let lm_ots_type = str32u(&consumed_data[..4]);
        consumed_data = &consumed_data[4..];

        let lm_ots_type = match LmotsAlgorithmType::from_u32(lm_ots_type) {
            None => return None,
            Some(x) => x,
        };

        let mut initial: IType = [0u8; 16];
        initial.copy_from_slice(&consumed_data[..16]);
        consumed_data = &consumed_data[16..];

        let q = str32u(&consumed_data[..4]);
        consumed_data = &consumed_data[4..];

        let mut seed: Seed = [0u8; 32];
        seed.copy_from_slice(&consumed_data[..32]);
        // consumed_data = &consumed_data[32..];

        let key = LmsPrivateKey {
            lms_type,
            lm_ots_type,
            seed,
            I: initial,
            q,
        };

        Some(key)
    }
}

#[allow(non_snake_case)]
#[derive(Debug, PartialEq, Eq)]
pub struct LmsPublicKey {
    pub lm_ots_type: LmotsAlgorithmType,
    pub lms_type: LmsAlgorithmType,
    pub key: DynamicArray<u8, MAX_M>,
    pub I: IType,
}

#[allow(non_snake_case)]
impl LmsPublicKey {
    pub fn new(
        public_key: DynamicArray<u8, MAX_M>,
        lm_ots_type: LmotsAlgorithmType,
        lms_type: LmsAlgorithmType,
        I: IType,
    ) -> Self {
        LmsPublicKey {
            lm_ots_type,
            lms_type,
            key: public_key,
            I,
        }
    }

    pub fn to_binary_representation(&self) -> DynamicArray<u8, { 4 + 4 + 16 + MAX_M }> {
        let mut result = DynamicArray::new();

        result.append(&u32str(self.lms_type as u32));
        result.append(&u32str(self.lm_ots_type as u32));

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

        let lms_type = match LmsAlgorithmType::from_u32(pubtype) {
            None => return None,
            Some(x) => x,
        };

        let ots_typecode = str32u(read_and_advance(data, 4, &mut data_index));

        let lm_ots_type = match LmotsAlgorithmType::from_u32(ots_typecode) {
            None => return None,
            Some(x) => x,
        };

        let lm_parameter = lms_type.get_parameter();

        if data.len() - data_index == 24 + lm_parameter.m as usize {
            return None;
        }

        let mut initial: IType = [0u8; 16];
        initial.clone_from_slice(read_and_advance(data, 16, &mut data_index));

        let mut key: DynamicArray<u8, MAX_M> = DynamicArray::new();

        key.append(&data[data_index..data_index + lm_parameter.m as usize]);

        let public_key = LmsPublicKey {
            lms_type,
            lm_ots_type,
            I: initial,
            key,
        };

        Some(public_key)
    }
}

#[cfg(test)]
mod tests {
    use crate::lms::keygen::{generate_private_key, generate_public_key};

    use super::{LmsPrivateKey, LmsPublicKey};

    #[test]
    fn test_private_key_binary_representation() {
        let lms_type = crate::LmsAlgorithmType::LmsSha256M32H5;
        let lmots_type = crate::LmotsAlgorithmType::LmotsSha256N32W2;

        let private_key = generate_private_key(lms_type, lmots_type);

        let serialized = private_key.to_binary_representation();
        let deserialized =
            LmsPrivateKey::from_binary_representation(&serialized.get_slice()).unwrap();

        assert!(private_key == deserialized);
    }

    #[test]
    fn test_public_key_binary_representation() {
        let lms_type = crate::LmsAlgorithmType::LmsSha256M32H5;
        let lmots_type = crate::LmotsAlgorithmType::LmotsSha256N32W2;

        let private_key = generate_private_key(lms_type, lmots_type);

        let public_key = generate_public_key(&private_key);

        let serialized = public_key.to_binary_representation();
        let deserialized = LmsPublicKey::from_binary_representation(serialized.get_slice())
            .expect("Deserialization must succeed.");

        assert!(public_key == deserialized);
    }
}
