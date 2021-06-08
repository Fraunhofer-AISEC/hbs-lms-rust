use std::iter::FromIterator;

use crate::lm_ots::definitions::QType;
use crate::lm_ots::signing::LmotsSignature;
use crate::lms::definitions::LmsAlgorithmParameter;
use crate::lms::definitions::LmsPrivateKey;
use crate::lms::definitions::LmsPublicKey;
use crate::util::helper::insert;
use crate::util::ustr::str32u;
use crate::util::ustr::u32str;
use crate::LmotsAlgorithmType;
use std::convert::TryInto;

pub struct LmsSignature {
    pub lms_parameter: LmsAlgorithmParameter,
    pub q: QType,
    pub lmots_signature: LmotsSignature,
    pub path: Vec<Vec<u8>>,
}

impl LmsSignature {
    pub fn sign(
        lms_private_key: &mut LmsPrivateKey,
        lms_public_key: &LmsPublicKey,
        message: &[u8],
    ) -> Result<LmsSignature, &'static str> {
        let lms_parameter = lms_private_key.lms_type.get_parameter();
        let lm_ots_private_key = lms_private_key.use_lmots_private_key()?;

        let tree = lms_public_key
            .tree
            .as_ref()
            .expect("TODO: Precomputed tree must be available at signing.");

        let ots_signature = LmotsSignature::sign(lm_ots_private_key, message);

        let h = lms_parameter.h;
        let mut i = 0usize;
        let r = 2usize.pow(h as u32) + str32u(&lm_ots_private_key.q) as usize;

        let mut path: Vec<Vec<u8>> = Vec::new();

        while i < h.into() {
            let temp = (r / (2usize.pow(i as u32))) ^ 0x1;
            path.push(tree[temp].clone());
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

    pub fn to_binary_representation(&self) -> Vec<u8> {
        let mut result = Vec::new();

        insert(&self.q, &mut result);

        let lmots_signature = self.lmots_signature.to_binary_representation();
        insert(&lmots_signature, &mut result);

        insert(&u32str(self.lms_parameter._type as u32), &mut result);

        let flattened_path = self.path.iter().flatten().map(|x| x.clone());
        let flattened_path = Vec::from_iter(flattened_path);

        insert(&flattened_path, &mut result);

        result
    }

    pub fn from_binary_representation(data: Vec<u8>) -> Option<Self> {
        // Parsing like 5.4.2 Algorithm 6a

        if data.len() < 8 {
            return None;
        }

        let mut data_index = 0;

        let q = str32u(data[data_index..data_index + 4].try_into().unwrap());
        data_index += 4;

        let ots_type = str32u(data[data_index..data_index + 4].try_into().unwrap());
        data_index += 4;

        let ots_type = match LmotsAlgorithmType::from_u32(ots_type) {
            None => return None,
            Some(x) => x,
        };

        let ots_parameter = ots_type.get_parameter();

        if data.len() - data_index < 12 + ots_parameter.n as usize * (ots_parameter.p as usize + 1)
        {
            return None;
        }

        todo!()
    }
}
