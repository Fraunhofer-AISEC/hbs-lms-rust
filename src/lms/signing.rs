use crate::lm_ots;
use crate::lm_ots::definitions::QType;
use crate::lm_ots::signing::LmotsSignature;
use crate::lms::definitions::LmsAlgorithmParameter;
use crate::lms::definitions::LmsPrivateKey;
use crate::lms::definitions::LmsPublicKey;
use crate::util::helper::insert;
use crate::util::ustr::str32u;
use crate::util::ustr::u32str;
use crate::LmotsAlgorithmType;
use crate::LmsAlgorithmType;
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

        let flattened_path: Vec<u8> = self.path.iter().flatten().copied().collect::<Vec<_>>();

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

        let lm_ots_parameter = ots_type.get_parameter();

        if data.len() - data_index
            < 12 + lm_ots_parameter.n as usize * (lm_ots_parameter.p as usize + 1)
        {
            return None;
        }

        let lmots_signature = match lm_ots::signing::LmotsSignature::from_binary_representation(
            &data.as_slice()
                [4..(7 + lm_ots_parameter.n as usize * (lm_ots_parameter.p as usize + 1))],
        ) {
            None => return None,
            Some(x) => x,
        };

        let lms_type_start = 8 + lm_ots_parameter.n as usize * (lm_ots_parameter.p as usize + 1);
        let lms_type_end = 11 + lm_ots_parameter.n as usize * (lm_ots_parameter.p as usize + 1);

        let lms_type = str32u(&data.as_slice()[lms_type_start..lms_type_end]);

        let lms_type = match LmsAlgorithmType::from_u32(lms_type) {
            None => return None,
            Some(x) => x,
        };

        let lms_parameter = lms_type.get_parameter();

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

        let mut tree_slice = data.as_slice();
        let tree_start = 12 + lm_ots_parameter.n as usize * (lm_ots_parameter.p as usize + 1);

        tree_slice = &tree_slice[tree_start..];

        let mut trees: Vec<Vec<u8>> = Vec::new();

        for _ in 0..lms_parameter.h {
            let mut path = vec![0u8; lms_parameter.m as usize];
            path.copy_from_slice(tree_slice);
            trees.push(path);

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
