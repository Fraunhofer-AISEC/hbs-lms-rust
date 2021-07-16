use crate::constants::*;
use crate::extract_or_return;
use crate::hasher::Hasher;
use crate::lm_ots;
use crate::lm_ots::definitions::LmotsPrivateKey;
use crate::lm_ots::parameters::LmotsAlgorithm;
use crate::lm_ots::parameters::LmotsParameter;
use crate::lms::parameters::LmsAlgorithm;
use crate::util::dynamic_array::DynamicArray;
use crate::util::helper::read_and_advance;
use crate::util::ustr::str32u;
use crate::util::ustr::u32str;

use super::parameters::LmsParameter;

#[derive(Debug, Default, Clone, Copy, PartialEq)]
pub struct LmsPrivateKey<H: Hasher> {
    pub I: IType,
    pub q: u32,
    pub seed: Seed,
    pub lmots_parameter: LmotsParameter<H>,
    pub lms_parameter: LmsParameter<H>,
}

impl<H: Hasher> LmsPrivateKey<H> {
    pub fn new(
        seed: Seed,
        I: IType,
        lmots_parameter: LmotsParameter<H>,
        lms_parameter: LmsParameter<H>,
    ) -> Self {
        LmsPrivateKey {
            seed,
            I,
            q: 0,
            lmots_parameter,
            lms_parameter,
        }
    }

    pub fn use_lmots_private_key(&mut self) -> Result<LmotsPrivateKey<H>, &'static str> {
        let number_of_lm_ots_keys = self.lms_parameter.number_of_lm_ots_keys();

        if self.q as usize >= number_of_lm_ots_keys {
            return Err("All private keys already used.");
        }

        self.q += 1;

        let key = lm_ots::generate_private_key(
            u32str(self.q - 1),
            self.I,
            self.seed,
            self.lmots_parameter,
        );

        Ok(key)
    }
}

#[derive(Debug, Clone, Default, PartialEq)]
pub struct LmsPublicKey<H: Hasher> {
    pub key: DynamicArray<u8, MAX_HASH>,
    pub I: IType,
    pub lmots_parameter: LmotsParameter<H>,
    pub lms_parameter: LmsParameter<H>,
}

impl<H: Hasher> LmsPublicKey<H> {
    pub fn new(
        public_key: DynamicArray<u8, MAX_HASH>,
        I: IType,
        lmots_parameter: LmotsParameter<H>,
        lms_parameter: LmsParameter<H>,
    ) -> Self {
        LmsPublicKey {
            key: public_key,
            I,
            lmots_parameter,
            lms_parameter,
        }
    }

    pub fn to_binary_representation(&self) -> DynamicArray<u8, MAX_LMS_PUBLIC_KEY_LENGTH> {
        let mut result = DynamicArray::new();

        result.append(&u32str(self.lms_parameter.get_type()));
        result.append(&u32str(self.lmots_parameter.get_type()));

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

        let lms_parameter = extract_or_return!(LmsAlgorithm::get_from_type(lms_type));

        let lm_ots_typecode = str32u(read_and_advance(data, 4, &mut data_index));

        let lmots_parameter = extract_or_return!(LmotsAlgorithm::get_from_type(lm_ots_typecode));

        if data.len() - data_index == 24 + lms_parameter.get_m() as usize {
            return None;
        }

        let mut initial: IType = [0u8; 16];
        initial.clone_from_slice(read_and_advance(data, 16, &mut data_index));

        let mut key: DynamicArray<u8, MAX_HASH> = DynamicArray::new();

        key.append(&data[data_index..data_index + lms_parameter.get_m() as usize]);

        let public_key = LmsPublicKey {
            I: initial,
            key,
            lmots_parameter,
            lms_parameter,
        };

        Some(public_key)
    }
}

#[cfg(test)]
mod tests {
    use crate::{
        hasher::sha256::Sha256Hasher,
        lm_ots::parameters::LmotsAlgorithm,
        lms::{
            keygen::{generate_private_key, generate_public_key},
            parameters::LmsAlgorithm,
        },
    };

    use super::LmsPublicKey;

    #[test]
    fn test_public_key_binary_representation() {
        let private_key = generate_private_key::<Sha256Hasher>(
            LmotsAlgorithm::construct_default_parameter(),
            LmsAlgorithm::construct_default_parameter(),
        );

        let public_key = generate_public_key(&private_key);

        let serialized = public_key.to_binary_representation();
        let deserialized = LmsPublicKey::from_binary_representation(serialized.as_slice())
            .expect("Deserialization must succeed.");

        assert!(public_key == deserialized);
    }
}
