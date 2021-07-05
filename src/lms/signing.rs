use core::marker::PhantomData;

use crate::constants::QType;
use crate::constants::MAX_H;
use crate::constants::MAX_M;
use crate::constants::MAX_N;
use crate::constants::MAX_P;
use crate::lm_ots;
use crate::lm_ots::parameter::LmotsParameter;
use crate::lm_ots::signing::LmotsSignature;
use crate::lms::definitions::LmsPrivateKey;
use crate::util::dynamic_array::DynamicArray;
use crate::util::ustr::str32u;
use crate::util::ustr::u32str;

use super::helper::get_tree_element;
use super::parameter::LmsParameter;

#[derive(Debug, Default, Clone)]
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
        let lm_ots_private_key = lms_private_key.use_lmots_private_key()?;

        let ots_signature = LmotsSignature::sign(&lm_ots_private_key, message);

        let h = <LMS>::H;
        let mut i = 0usize;
        let r = 2usize.pow(h as u32) + str32u(&lm_ots_private_key.q) as usize;

        let mut path: DynamicArray<DynamicArray<u8, MAX_M>, MAX_H> = DynamicArray::new();

        while i < h.into() {
            let tree_index = (r / (2usize.pow(i as u32))) ^ 0x1;
            path.push(get_tree_element(tree_index, &lms_private_key));
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

        result.append(&u32str(<LMS>::TYPE as u32));

        for element in self.path.iter() {
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

        if !<OTS>::is_type_correct(lm_ots_type) {
            return None;
        }

        let n = <OTS>::N;
        let p = <OTS>::get_p();

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

        if !<LMS>::is_type_correct(lms_type) {
            return None;
        }

        if q >= 2u32.pow(<LMS>::H as u32) {
            return None;
        }

        if data.len() != 12 + n as usize * (p as usize + 1) + <LMS>::M as usize * <LMS>::H as usize
        {
            return None;
        }

        let mut tree_slice = data;
        let tree_start = 12 + <OTS>::N as usize * (<OTS>::get_p() as usize + 1);

        tree_slice = &tree_slice[tree_start..];

        let mut trees: DynamicArray<DynamicArray<u8, MAX_M>, MAX_H> = DynamicArray::new();

        for _ in 0..<LMS>::H {
            let mut path = DynamicArray::new();
            path.append(&tree_slice[..<LMS>::M as usize]);
            trees.push(path);

            tree_slice = &tree_slice[<LMS>::M as usize..];
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
