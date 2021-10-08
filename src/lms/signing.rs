use crate::constants::LmsLeafIdentifier;
use crate::constants::MAX_H;
use crate::constants::MAX_HASH;
use crate::constants::MAX_LMS_SIGNATURE_LENGTH;
use crate::extract_or_return;
use crate::hasher::Hasher;
use crate::lm_ots;
use crate::lm_ots::parameters::LmotsAlgorithm;
use crate::lm_ots::signing::InMemoryLmotsSignature;
use crate::lm_ots::signing::LmotsSignature;
use crate::lms::definitions::LmsPrivateKey;
use crate::lms::parameters::LmsAlgorithm;
use crate::util::ustr::str32u;
use crate::util::ustr::u32str;
use arrayvec::ArrayVec;

use super::helper::get_tree_element;
use super::parameters::LmsParameter;

#[derive(Debug, Default, Clone, PartialEq)]
pub struct LmsSignature<H: Hasher> {
    pub q: LmsLeafIdentifier,
    pub lmots_signature: LmotsSignature<H>,
    pub path: ArrayVec<ArrayVec<u8, MAX_HASH>, MAX_H>,
    pub lms_parameter: LmsParameter<H>,
}

#[derive(Clone)]
pub struct InMemoryLmsSignature<'a, H: Hasher> {
    pub q: u32,
    pub lmots_signature: InMemoryLmotsSignature<'a, H>,
    pub path: &'a [u8],
    pub lms_parameter: LmsParameter<H>,
}

impl<'a, H: Hasher> PartialEq<LmsSignature<H>> for InMemoryLmsSignature<'a, H> {
    fn eq(&self, other: &LmsSignature<H>) -> bool {
        let first_condition = self.q == str32u(&other.q[..])
            && self.lmots_signature == other.lmots_signature
            && self.lms_parameter == other.lms_parameter;

        if !first_condition {
            return false;
        }

        let mut curr = self.path;

        for x in other.path.iter() {
            for y in x.iter() {
                if curr[0] != *y {
                    return false;
                }
                curr = &curr[1..];
            }
        }

        true
    }
}

impl<H: Hasher> LmsSignature<H> {
    pub fn sign(
        lms_private_key: &mut LmsPrivateKey<H>,
        message: &[u8],
    ) -> Result<LmsSignature<H>, ()> {
        let lm_ots_private_key = lms_private_key.use_lmots_private_key()?;

        let ots_signature = LmotsSignature::sign(&lm_ots_private_key, message);

        let height = lms_private_key.lms_parameter.get_height();
        let mut i = 0usize;
        let r =
            2usize.pow(height as u32) + str32u(&lm_ots_private_key.lms_leaf_identifier) as usize;

        let mut path: ArrayVec<ArrayVec<u8, MAX_HASH>, MAX_H> = ArrayVec::new();

        while i < height.into() {
            let tree_index = (r / (2usize.pow(i as u32))) ^ 0x1;
            path.push(get_tree_element(tree_index, lms_private_key, &mut None));
            i += 1;
        }

        let signature = LmsSignature {
            q: lm_ots_private_key.lms_leaf_identifier,
            lmots_signature: ots_signature,
            path,
            lms_parameter: lms_private_key.lms_parameter,
        };

        Ok(signature)
    }

    pub fn to_binary_representation(&self) -> ArrayVec<u8, MAX_LMS_SIGNATURE_LENGTH> {
        let mut result = ArrayVec::new();

        result.try_extend_from_slice(&self.q).unwrap();

        let lmots_signature = self.lmots_signature.to_binary_representation();

        result
            .try_extend_from_slice(lmots_signature.as_slice())
            .unwrap();

        result
            .try_extend_from_slice(&u32str(self.lms_parameter.get_type() as u32))
            .unwrap();

        for element in self.path.iter() {
            result.try_extend_from_slice(element.as_slice()).unwrap();
        }

        result
    }
}

impl<'a, H: Hasher> InMemoryLmsSignature<'a, H> {
    pub fn new(data: &'a [u8]) -> Option<Self> {
        // Parsing like 5.4.2 Algorithm 6a

        if data.len() < 8 {
            return None;
        }

        let mut consumed_data = data;

        let lms_leaf_identifier = str32u(&consumed_data[..4]);
        consumed_data = &consumed_data[4..];

        let lm_ots_type = str32u(&consumed_data[..4]);
        // consumed_data = &consumed_data[4..];

        let lmots_parameter = extract_or_return!(LmotsAlgorithm::get_from_type::<H>(lm_ots_type));

        let n = lmots_parameter.get_n();
        let p = lmots_parameter.get_p();

        if data.len() < 12 + n as usize * (p as usize + 1) {
            return None;
        }

        let lmots_signature = match lm_ots::signing::InMemoryLmotsSignature::new(
            &data[4..=(7 + n as usize * (p as usize + 1))],
        ) {
            None => return None,
            Some(x) => x,
        };

        let lms_type_start = 8 + n as usize * (p as usize + 1);
        let lms_type_end = 11 + n as usize * (p as usize + 1);

        let lms_type = str32u(&data[lms_type_start..=lms_type_end]);

        let lms_parameter = extract_or_return!(LmsAlgorithm::get_from_type(lms_type));

        let tree_height = lms_parameter.get_height();

        if lms_leaf_identifier >= 2u32.pow(tree_height as u32) {
            return None;
        }

        let m = lms_parameter.get_m();

        if data.len() < 12 + n as usize * (p as usize + 1) + m as usize * tree_height as usize {
            return None;
        }

        let mut tree_slice = data;
        let tree_start =
            12 + lmots_parameter.get_n() as usize * (lmots_parameter.get_p() as usize + 1);

        tree_slice = &tree_slice[tree_start..];

        let trees: &[u8] = &tree_slice[..lms_parameter.get_m() * tree_height as usize];

        let signature = Self {
            lms_parameter,
            q: lms_leaf_identifier,
            lmots_signature,
            path: trees,
        };

        Some(signature)
    }

    pub fn get_path(&self, index: usize) -> &[u8] {
        let step = self.lms_parameter.get_m();
        let start = step * index;
        let end = start + step;
        &self.path[start..end]
    }
}

#[cfg(test)]
mod tests {
    use crate::{
        lm_ots::parameters::LmotsAlgorithm,
        lms::{
            keygen::generate_private_key, parameters::LmsAlgorithm, signing::InMemoryLmsSignature,
        },
    };

    use super::LmsSignature;

    #[test]
    fn test_binary_representation_of_signature() {
        let mut private_key = generate_private_key(
            LmotsAlgorithm::construct_default_parameter(),
            LmsAlgorithm::construct_default_parameter(),
        );

        let message = "Hi, what up?".as_bytes();

        let signature =
            LmsSignature::sign(&mut private_key, message).expect("Signing must succeed.");

        let binary = signature.to_binary_representation();

        let deserialized =
            InMemoryLmsSignature::new(&binary.as_slice()).expect("Deserialization must succeed.");

        assert!(deserialized == signature);
    }
}
