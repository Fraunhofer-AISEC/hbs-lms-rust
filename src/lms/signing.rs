use crate::constants::MAX_H;
use crate::constants::MAX_M;
use crate::constants::MAX_N;
use crate::constants::MAX_P;
use crate::lm_ots;
use crate::lm_ots::definitions::LmotsAlgorithmParameter;
use crate::lm_ots::definitions::QType;
use crate::lm_ots::signing::LmotsSignature;
use crate::lms::definitions::LmsAlgorithmParameter;
use crate::lms::definitions::LmsPrivateKey;
use crate::util::dynamic_array::DynamicArray;
use crate::util::ustr::str32u;
use crate::util::ustr::u32str;
use crate::LmotsAlgorithmType;
use crate::LmsAlgorithmType;

use super::helper::get_tree_element;

#[derive(Debug, PartialEq, Eq)]
pub struct LmsSignature {
    pub lms_parameter: LmsAlgorithmParameter,
    pub q: QType,
    pub lmots_signature: LmotsSignature,
    pub path: DynamicArray<DynamicArray<u8, MAX_M>, MAX_H>,
}

impl LmsSignature {
    pub fn sign(
        lms_private_key: &mut LmsPrivateKey,
        message: &[u8],
    ) -> Result<LmsSignature, &'static str> {
        let lms_parameter = lms_private_key.lms_parameter;
        let lm_ots_private_key = lms_private_key.use_lmots_private_key()?;

        let ots_signature = LmotsSignature::sign(&lm_ots_private_key, message);

        let h = lms_parameter.h;
        let mut i = 0usize;
        let r = 2usize.pow(h as u32) + str32u(&lm_ots_private_key.q) as usize;

        let mut path: DynamicArray<DynamicArray<u8, MAX_M>, MAX_H> = DynamicArray::new();

        while i < h.into() {
            let tree_index = (r / (2usize.pow(i as u32))) ^ 0x1;
            path[i] = get_tree_element(tree_index, &lms_private_key);
            i += 1;
        }

        let signature = LmsSignature {
            lms_parameter,
            q: lm_ots_private_key.q,
            lmots_signature: ots_signature,
            path,
        };

        Ok(signature)
    }

    pub fn to_binary_representation(
        &self,
    ) -> DynamicArray<u8, { 4 + (4 + MAX_N + (MAX_N * MAX_P)) + 4 + (MAX_M * MAX_H) }> {
        let mut result = DynamicArray::new();

        result.append(&self.q);

        let lmots_signature = self.lmots_signature.to_binary_representation();

        result.append(&lmots_signature.get_slice());

        result.append(&u32str(self.lms_parameter._type as u32));

        for element in self.path.into_iter() {
            result.append(element.get_slice());
        }

        result
    }

    pub fn from_binary_representation(data: &[u8]) -> Option<Self> {
        // Parsing like 5.4.2 Algorithm 6a

        if data.len() < 8 {
            return None;
        }

        let mut consumed_data = data;

        let q = str32u(&consumed_data[..4]);
        consumed_data = &consumed_data[4..];

        let ots_type = str32u(&consumed_data[..4]);
        // consumed_data = &consumed_data[4..];

        let ots_type = match LmotsAlgorithmType::from_u32(ots_type) {
            None => return None,
            Some(x) => x,
        };

        let lm_ots_parameter = LmotsAlgorithmParameter::new(ots_type);

        if data.len() < 12 + lm_ots_parameter.n as usize * (lm_ots_parameter.p as usize + 1) {
            return None;
        }

        let lmots_signature = match lm_ots::signing::LmotsSignature::from_binary_representation(
            &data[4..=(7 + lm_ots_parameter.n as usize * (lm_ots_parameter.p as usize + 1))],
        ) {
            None => return None,
            Some(x) => x,
        };

        let lms_type_start = 8 + lm_ots_parameter.n as usize * (lm_ots_parameter.p as usize + 1);
        let lms_type_end = 11 + lm_ots_parameter.n as usize * (lm_ots_parameter.p as usize + 1);

        let lms_type = str32u(&data[lms_type_start..=lms_type_end]);

        let lms_parameter = match LmsAlgorithmType::from_u32(lms_type) {
            None => return None,
            Some(x) => LmsAlgorithmParameter::new(x),
        };

        if q >= 2u32.pow(lms_parameter.h as u32) {
            return None;
        }

        if data.len()
            != 12
                + lm_ots_parameter.n as usize * (lm_ots_parameter.p as usize + 1)
                + lms_parameter.m as usize * lms_parameter.h as usize
        {
            return None;
        }

        let mut tree_slice = data;
        let tree_start = 12 + lm_ots_parameter.n as usize * (lm_ots_parameter.p as usize + 1);

        tree_slice = &tree_slice[tree_start..];

        let mut trees: DynamicArray<DynamicArray<u8, MAX_M>, MAX_H> = DynamicArray::new();

        for i in 0..lms_parameter.h {
            let mut path = DynamicArray::new();
            path.append(&tree_slice[..lms_parameter.m as usize]);
            trees[i as usize] = path;

            tree_slice = &tree_slice[lms_parameter.m as usize..];
        }

        let signature = Self {
            lms_parameter,
            lmots_signature,
            q: u32str(q),
            path: trees,
        };

        Some(signature)
    }
}

#[cfg(test)]
mod tests {
    use crate::{
        lm_ots::definitions::LmotsAlgorithmParameter,
        lms::{definitions::LmsAlgorithmParameter, keygen::generate_private_key},
    };

    use super::LmsSignature;

    #[test]
    fn test_binary_representation_of_signature() {
        let lms_type = LmsAlgorithmParameter::new(crate::LmsAlgorithmType::LmsSha256M32H5);
        let lmots_type = LmotsAlgorithmParameter::new(crate::LmotsAlgorithmType::LmotsSha256N32W2);

        let mut private_key = generate_private_key(lms_type, lmots_type);

        let message = "Hi, what up?".as_bytes();

        let signature =
            LmsSignature::sign(&mut private_key, message).expect("Signing must succeed.");

        let binary = signature.to_binary_representation();

        let deserialized = LmsSignature::from_binary_representation(&binary.get_slice())
            .expect("Deserialization must succeed.");

        assert!(signature == deserialized);
    }
}
