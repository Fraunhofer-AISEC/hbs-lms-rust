use crate::extract_or_return;
use crate::hasher::Hasher;
use crate::lm_ots::parameters::LmotsAlgorithm;
use crate::util::dynamic_array::DynamicArray;
use crate::{
    constants::{D_MESG, MAX_HASH, MAX_P},
    util::{
        coef::coef,
        random::get_random,
        ustr::{str32u, u32str},
    },
};
use core::usize;

use super::definitions::LmotsPrivateKey;
use super::parameters::LmotsParameter;

#[derive(Debug, Default, Clone, PartialEq)]
pub struct LmotsSignature<H: Hasher> {
    pub C: DynamicArray<u8, MAX_HASH>,
    pub y: DynamicArray<DynamicArray<u8, MAX_HASH>, MAX_P>,
    pub lmots_parameter: LmotsParameter<H>,
}

impl<H: Hasher> LmotsSignature<H> {
    pub fn sign(private_key: &LmotsPrivateKey<H>, message: &[u8]) -> Self {
        let mut C = DynamicArray::new();

        let lmots_parameter = private_key.lmots_parameter;

        let mut hasher = lmots_parameter.get_hasher();

        unsafe {
            C.set_size(lmots_parameter.get_n() as usize);
        }

        get_random(C.as_mut_slice());

        hasher.update(&private_key.I);
        hasher.update(&private_key.q);
        hasher.update(&D_MESG);
        hasher.update(&C.as_slice());
        hasher.update(message);

        let Q: DynamicArray<u8, MAX_HASH> = hasher.finalize_reset();
        let Q_and_checksum = lmots_parameter.get_appended_with_checksum(&Q.as_slice());

        let mut y: DynamicArray<DynamicArray<u8, MAX_HASH>, MAX_P> = DynamicArray::new();

        for i in 0..lmots_parameter.get_p() {
            let a = coef(
                &Q_and_checksum.as_slice(),
                i as u64,
                lmots_parameter.get_winternitz() as u64,
            ) as usize;
            let mut tmp = private_key.key[i as usize].clone();

            hasher.do_hash_chain(&private_key.I, &private_key.q, i, 0, a, tmp.as_mut_slice());

            y.push(tmp);
        }

        LmotsSignature {
            C,
            y,
            lmots_parameter,
        }
    }

    pub fn to_binary_representation(
        &self,
    ) -> DynamicArray<u8, { 4 + MAX_HASH + (MAX_HASH * MAX_P) }> {
        let mut result = DynamicArray::new();

        result.append(&u32str(self.lmots_parameter.get_type()));
        result.append(self.C.as_slice());

        for x in self.y.iter() {
            for y in x.iter() {
                result.append(&[*y]);
            }
        }

        result
    }

    pub fn from_binary_representation(data: &[u8]) -> Option<Self> {
        if data.len() < 4 {
            return None;
        }

        let mut consumed_data = data;

        let lm_ots_type = str32u(&consumed_data[..4]);
        consumed_data = &consumed_data[4..];

        let lmots_parameter = extract_or_return!(LmotsAlgorithm::get_from_type(lm_ots_type));

        let n = lmots_parameter.get_n();
        let p = lmots_parameter.get_p();

        if data.len() != 4 + n as usize * (p as usize + 1) {
            return None;
        }

        let mut C = DynamicArray::new();

        C.append(&consumed_data[..n as usize]);
        consumed_data = &consumed_data[n as usize..];

        let mut y = DynamicArray::new();

        for _ in 0..p {
            let mut temp = DynamicArray::new();
            temp.append(&consumed_data[..n as usize]);
            y.push(temp);

            consumed_data = &consumed_data[n as usize..];
        }

        let signature = Self {
            C,
            y,
            lmots_parameter,
        };

        Some(signature)
    }
}

#[cfg(test)]
mod tests {
    use crate::{
        constants::{MAX_HASH, MAX_P},
        lm_ots::parameters::LmotsAlgorithm,
        util::dynamic_array::DynamicArray,
    };

    use super::LmotsSignature;

    #[test]
    fn test_binary_representation() {
        let lmots_parameter = LmotsAlgorithm::construct_default_parameter();

        let mut c = DynamicArray::new();
        let mut y: DynamicArray<DynamicArray<u8, MAX_HASH>, MAX_P> = DynamicArray::new();

        for i in 0..lmots_parameter.get_n() as usize {
            c.push(i as u8);
        }

        for i in 0..lmots_parameter.get_p() as usize {
            y.push(DynamicArray::new());
            for j in 0..lmots_parameter.get_n() as usize {
                y[i].push(j as u8);
            }
        }

        let signature = LmotsSignature {
            C: c,
            y,
            lmots_parameter,
        };

        let binary_rep = signature.to_binary_representation();
        let deserialized_signature =
            LmotsSignature::from_binary_representation(binary_rep.as_slice())
                .expect("Deserialization must succeed.");

        assert!(signature == deserialized_signature);
    }
}
