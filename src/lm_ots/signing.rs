use crate::util::dynamic_array::DynamicArray;
use crate::{
    constants::{D_MESG, MAX_N, MAX_P},
    util::{
        coef::coef,
        random::get_random,
        ustr::{str32u, u32str},
    },
};
use core::marker::PhantomData;
use core::usize;

use super::definitions::LmotsPrivateKey;
use super::parameter::LmotsParameter;

#[allow(non_snake_case)]
#[derive(Debug, Default, Clone)]
pub struct LmotsSignature<OTS: LmotsParameter> {
    pub C: DynamicArray<u8, MAX_N>,
    pub y: DynamicArray<DynamicArray<u8, MAX_N>, MAX_P>,
    lmots_parameter: PhantomData<OTS>,
}

impl<OTS: LmotsParameter> PartialEq for LmotsSignature<OTS> {
    fn eq(&self, other: &Self) -> bool {
        self.C == other.C && self.y == other.y && self.lmots_parameter == other.lmots_parameter
    }
}

impl<OTS: LmotsParameter> Eq for LmotsSignature<OTS> {}

impl<OTS: LmotsParameter> LmotsSignature<OTS> {
    #[allow(non_snake_case)]
    pub fn sign(private_key: &LmotsPrivateKey<OTS>, message: &[u8]) -> Self {
        let mut C = DynamicArray::new();

        let mut hasher = <OTS>::get_hasher();

        unsafe {
            C.set_size(<OTS>::N as usize);
        }

        get_random(C.get_mut_slice());

        hasher.update(&private_key.I);
        hasher.update(&private_key.q);
        hasher.update(&D_MESG);
        hasher.update(&C.get_slice());
        hasher.update(message);

        let Q: DynamicArray<u8, MAX_N> = hasher.finalize_reset();
        let Q_and_checksum = <OTS>::get_appended_with_checksum(&Q.get_slice());

        let mut y: DynamicArray<DynamicArray<u8, MAX_N>, MAX_P> = DynamicArray::new();

        for i in 0..<OTS>::get_p() {
            let a = coef(&Q_and_checksum.get_slice(), i as u64, <OTS>::W as u64) as usize;
            let mut tmp = private_key.key[i as usize].clone();

            hasher.do_hash_chain(&private_key.I, &private_key.q, i, 0, a, tmp.get_mut_slice());

            y.push(tmp);
        }

        LmotsSignature {
            C,
            y,
            lmots_parameter: PhantomData,
        }
    }

    pub fn to_binary_representation(&self) -> DynamicArray<u8, { 4 + MAX_N + (MAX_N * MAX_P) }> {
        let mut result = DynamicArray::new();

        result.append(&u32str(<OTS>::TYPE));
        result.append(self.C.get_slice());

        for x in self.y.iter() {
            for y in x.iter() {
                result.append(&[*y]);
            }
        }

        result
    }

    #[allow(non_snake_case)]
    pub fn from_binary_representation(data: &[u8]) -> Option<Self> {
        if data.len() < 4 {
            return None;
        }

        let mut consumed_data = data;

        let lm_ots_type = str32u(&consumed_data[..4]);
        consumed_data = &consumed_data[4..];

        if !<OTS>::is_type_correct(lm_ots_type) {
            return None;
        }

        let n = <OTS>::N;
        let p = <OTS>::get_p();

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
            lmots_parameter: PhantomData,
        };

        Some(signature)
    }
}

#[cfg(test)]
mod tests {
    use core::marker::PhantomData;

    use crate::{
        constants::{MAX_N, MAX_P},
        util::dynamic_array::DynamicArray,
    };

    use super::LmotsSignature;
    use crate::LmotsParameter;

    #[test]
    fn test_binary_representation() {
        type LmotsType = crate::lm_ots::parameter::LmotsSha256N32W2;

        let mut c = DynamicArray::new();
        let mut y: DynamicArray<DynamicArray<u8, MAX_N>, MAX_P> = DynamicArray::new();

        for i in 0..<LmotsType>::N as usize {
            c.push(i as u8);
        }

        for i in 0..<LmotsType>::get_p() as usize {
            y.push(DynamicArray::new());
            for j in 0..<LmotsType>::N as usize {
                y[i].push(j as u8);
            }
        }

        let signature: LmotsSignature<crate::lm_ots::parameter::LmotsSha256N32W2> =
            LmotsSignature {
                C: c,
                y,
                lmots_parameter: PhantomData,
            };

        let binary_rep = signature.to_binary_representation();
        let deserialized_signature =
            LmotsSignature::<crate::lm_ots::parameter::LmotsSha256N32W2>::from_binary_representation(binary_rep.get_slice())
                .expect("Deserialization must succeed.");

        assert!(signature == deserialized_signature);
    }
}
