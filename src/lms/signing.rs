use core::marker::PhantomData;

use crate::constants::MAX_H;
use crate::constants::MAX_M;
use crate::constants::MAX_N;
use crate::constants::MAX_P;
use crate::lm_ots;
use crate::lm_ots::definitions::QType;
use crate::lm_ots::parameter::LmotsParameter;
use crate::lm_ots::signing::LmotsSignature;
use crate::lms::definitions::LmsPrivateKey;
use crate::util::dynamic_array::DynamicArray;
use crate::util::ustr::str32u;
use crate::util::ustr::u32str;

use super::helper::get_tree_element;
use super::parameter::LmsParameter;

#[derive(Debug)]
pub struct LmsSignature<OTS: LmotsParameter, LMS: LmsParameter> {
    pub q: QType,
    pub lmots_signature: LmotsSignature<OTS>,
    pub path: DynamicArray<DynamicArray<u8, MAX_M>, MAX_H>,
    lms_parameter: PhantomData<LMS>,
}

impl<OTS: LmotsParameter, LMS: LmsParameter> PartialEq for LmsSignature<OTS, LMS> {
    fn eq(&self, other: &Self) -> bool {
        self.q == other.q
            && self.lmots_signature == other.lmots_signature
            && self.path == other.path
            && self.lms_parameter == other.lms_parameter
    }
}

impl<OTS: LmotsParameter, LMS: LmsParameter> Eq for LmsSignature<OTS, LMS> {}

impl<OTS: LmotsParameter, LMS: LmsParameter> LmsSignature<OTS, LMS> {
    pub fn sign(
        lms_private_key: &mut LmsPrivateKey<OTS, LMS>,
        message: &[u8],
    ) -> Result<LmsSignature<OTS, LMS>, &'static str> {
        let lms_parameter = <LMS>::new();
        let lm_ots_private_key = lms_private_key.use_lmots_private_key()?;

        let ots_signature = LmotsSignature::sign(&lm_ots_private_key, message);

        let h = lms_parameter.get_h();
        let mut i = 0usize;
        let r = 2usize.pow(h as u32) + str32u(&lm_ots_private_key.q) as usize;

        let mut path: DynamicArray<DynamicArray<u8, MAX_M>, MAX_H> = DynamicArray::new();

        while i < h.into() {
            let tree_index = (r / (2usize.pow(i as u32))) ^ 0x1;
            path[i] = get_tree_element(tree_index, &lms_private_key);
            i += 1;
        }

        let signature = LmsSignature {
            q: lm_ots_private_key.q,
            lmots_signature: ots_signature,
            path,
            lms_parameter: PhantomData,
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

        let lms_parameter = <LMS>::new();

        result.append(&u32str(lms_parameter.get_type() as u32));

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

        let lm_ots_type = str32u(&consumed_data[..4]);
        // consumed_data = &consumed_data[4..];

        let lm_ots_parameter = <OTS>::new();

        if !lm_ots_parameter.is_type_correct(lm_ots_type) {
            return None;
        }

        let lm_ots_parameter = <OTS>::new();

        let n = <OTS>::N;
        let p = lm_ots_parameter.get_p();

        if data.len() < 12 + n as usize * (p as usize + 1) {
            return None;
        }

        let lmots_signature = match lm_ots::signing::LmotsSignature::from_binary_representation(
            &data[4..=(7 + n as usize * (p as usize + 1))],
        ) {
            None => return None,
            Some(x) => x,
        };

        let lms_type_start = 8 + n as usize * (p as usize + 1);
        let lms_type_end = 11 + n as usize * (p as usize + 1);

        let lms_type = str32u(&data[lms_type_start..=lms_type_end]);

        let lms_parameter = <LMS>::new();

        if !lms_parameter.is_type_correct(lms_type) {
            return None;
        }

        if q >= 2u32.pow(lms_parameter.get_h() as u32) {
            return None;
        }

        if data.len()
            != 12
                + n as usize * (p as usize + 1)
                + lms_parameter.get_m() as usize * lms_parameter.get_h() as usize
        {
            return None;
        }

        let mut tree_slice = data;
        let tree_start = 12 + <OTS>::N as usize * (lm_ots_parameter.get_p() as usize + 1);

        tree_slice = &tree_slice[tree_start..];

        let mut trees: DynamicArray<DynamicArray<u8, MAX_M>, MAX_H> = DynamicArray::new();

        for i in 0..lms_parameter.get_h() {
            let mut path = DynamicArray::new();
            path.append(&tree_slice[..lms_parameter.get_m() as usize]);
            trees[i as usize] = path;

            tree_slice = &tree_slice[lms_parameter.get_m() as usize..];
        }

        let signature = Self {
            lmots_signature,
            q: u32str(q),
            path: trees,
            lms_parameter: PhantomData,
        };

        Some(signature)
    }
}

#[cfg(test)]
mod tests {
    use crate::{
        lm_ots,
        lms::{self, keygen::generate_private_key},
    };

    use super::LmsSignature;

    #[test]
    fn test_binary_representation_of_signature() {
        let mut private_key = generate_private_key::<
            lm_ots::parameter::LmotsSha256N32W2,
            lms::parameter::LmsSha256M32H5,
        >();

        let message = "Hi, what up?".as_bytes();

        let signature =
            LmsSignature::sign(&mut private_key, message).expect("Signing must succeed.");

        let binary = signature.to_binary_representation();

        let deserialized = LmsSignature::from_binary_representation(&binary.get_slice())
            .expect("Deserialization must succeed.");

        assert!(signature == deserialized);
    }
}
