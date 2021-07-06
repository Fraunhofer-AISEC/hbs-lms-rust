use core::marker::PhantomData;

use crate::constants::*;
use crate::lm_ots;
use crate::lm_ots::definitions::LmotsPrivateKey;
use crate::lm_ots::parameter::LmotsParameter;
use crate::util::dynamic_array::DynamicArray;
use crate::util::helper::read_and_advance;
use crate::util::ustr::str32u;
use crate::util::ustr::u32str;

use super::parameter::LmsParameter;

#[allow(non_snake_case)]
#[derive(Debug, Default, Clone, Copy)]
pub struct LmsPrivateKey<OTS: LmotsParameter, LMS: LmsParameter> {
    pub I: IType,
    pub q: u32,
    pub seed: Seed,
    lmots_parameter: PhantomData<OTS>,
    lms_parameter: PhantomData<LMS>,
}

impl<OTS: LmotsParameter, LMS: LmsParameter> PartialEq for LmsPrivateKey<OTS, LMS> {
    fn eq(&self, other: &Self) -> bool {
        self.I == other.I
            && self.q == other.q
            && self.seed == other.seed
            && self.lmots_parameter == other.lmots_parameter
            && self.lms_parameter == other.lms_parameter
    }
}

impl<OTS: LmotsParameter, LMS: LmsParameter> Eq for LmsPrivateKey<OTS, LMS> {}

#[allow(non_snake_case)]
impl<OTS: LmotsParameter, LMS: LmsParameter> LmsPrivateKey<OTS, LMS> {
    pub fn new(seed: Seed, I: IType) -> Self {
        LmsPrivateKey {
            seed,
            I,
            q: 0,
            lmots_parameter: PhantomData,
            lms_parameter: PhantomData,
        }
    }

    pub fn use_lmots_private_key(&mut self) -> Result<LmotsPrivateKey<OTS>, &'static str> {
        if self.q as usize >= <LMS>::number_of_lm_ots_keys() {
            return Err("All private keys already used.");
        }
        self.q += 1;
        let key = lm_ots::generate_private_key(u32str(self.q - 1), self.I, self.seed);
        Ok(key)
    }

    pub fn to_binary_representation(&self) -> DynamicArray<u8, MAX_LMS_PRIVATE_KEY_LENGTH> {
        let mut result = DynamicArray::new();

        result.append(&u32str(<LMS>::TYPE as u32));
        result.append(&u32str(<OTS>::TYPE));

        result.append(&self.I);
        result.append(&u32str(self.q));
        result.append(&self.seed);

        result
    }

    pub fn from_binary_representation(data: &[u8]) -> Option<Self> {
        let mut consumed_data = data;

        let lms_type = str32u(&consumed_data[..4]);
        consumed_data = &consumed_data[4..];

        if !<LMS>::is_type_correct(lms_type) {
            return None;
        }

        let lm_ots_type = str32u(&consumed_data[..4]);
        consumed_data = &consumed_data[4..];

        if !<OTS>::is_type_correct(lm_ots_type) {
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
            seed,
            I: initial,
            q,
            lmots_parameter: PhantomData,
            lms_parameter: PhantomData,
        };

        Some(key)
    }

    pub fn get_h(&self) -> u8 {
        <LMS>::H
    }
}

#[allow(non_snake_case)]
#[derive(Debug, Clone, Default)]
pub struct LmsPublicKey<OTS: LmotsParameter, LMS: LmsParameter> {
    pub key: DynamicArray<u8, MAX_M>,
    pub I: IType,
    lmots_parameter: PhantomData<OTS>,
    lms_parameter: PhantomData<LMS>,
}

impl<OTS: LmotsParameter, LMS: LmsParameter> PartialEq for LmsPublicKey<OTS, LMS> {
    fn eq(&self, other: &Self) -> bool {
        self.key == other.key
            && self.I == other.I
            && self.lmots_parameter == other.lmots_parameter
            && self.lms_parameter == other.lms_parameter
    }
}

impl<OTS: LmotsParameter, LMS: LmsParameter> Eq for LmsPublicKey<OTS, LMS> {}

#[allow(non_snake_case)]
impl<OTS: LmotsParameter, LMS: LmsParameter> LmsPublicKey<OTS, LMS> {
    pub fn new(public_key: DynamicArray<u8, MAX_M>, I: IType) -> Self {
        LmsPublicKey {
            key: public_key,
            I,
            lmots_parameter: PhantomData,
            lms_parameter: PhantomData,
        }
    }

    pub fn to_binary_representation(&self) -> DynamicArray<u8, MAX_LMS_PUBLIC_KEY_LENGTH> {
        let mut result = DynamicArray::new();

        result.append(&u32str(<LMS>::TYPE));
        result.append(&u32str(<OTS>::TYPE));

        result.append(&self.I);
        result.append(&self.key.as_slice());

        result
    }

    pub fn from_binary_representation(data: &[u8]) -> Option<Self> {
        // Parsing like desribed in 5.4.2
        if data.len() < 8 {
            return None;
        }

        let mut data_index = 0;

        let lms_type = str32u(read_and_advance(data, 4, &mut data_index));

        if !<LMS>::is_type_correct(lms_type) {
            return None;
        }

        let lm_ots_typecode = str32u(read_and_advance(data, 4, &mut data_index));

        if !<OTS>::is_type_correct(lm_ots_typecode) {
            return None;
        }

        if data.len() - data_index == 24 + <LMS>::M as usize {
            return None;
        }

        let mut initial: IType = [0u8; 16];
        initial.clone_from_slice(read_and_advance(data, 16, &mut data_index));

        let mut key: DynamicArray<u8, MAX_M> = DynamicArray::new();

        key.append(&data[data_index..data_index + <LMS>::M as usize]);

        let public_key = LmsPublicKey {
            I: initial,
            key,
            lmots_parameter: PhantomData,
            lms_parameter: PhantomData,
        };

        Some(public_key)
    }
}

#[cfg(test)]
mod tests {
    use crate::{
        lm_ots,
        lms::{
            self,
            keygen::{generate_private_key, generate_public_key},
        },
    };

    use super::{LmsPrivateKey, LmsPublicKey};

    #[test]
    fn test_private_key_binary_representation() {
        let private_key = generate_private_key::<
            lm_ots::parameter::LmotsSha256N32W2,
            lms::parameter::LmsSha256M32H5,
        >();

        let serialized = private_key.to_binary_representation();
        let deserialized =
            LmsPrivateKey::from_binary_representation(&serialized.as_slice()).unwrap();

        assert!(private_key == deserialized);
    }

    #[test]
    fn test_public_key_binary_representation() {
        let private_key = generate_private_key::<
            lm_ots::parameter::LmotsSha256N32W2,
            lms::parameter::LmsSha256M32H5,
        >();

        let public_key = generate_public_key(&private_key);

        let serialized = public_key.to_binary_representation();
        let deserialized = LmsPublicKey::from_binary_representation(serialized.as_slice())
            .expect("Deserialization must succeed.");

        assert!(public_key == deserialized);
    }
}
