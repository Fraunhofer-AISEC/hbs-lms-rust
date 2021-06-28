use crate::util::dynamic_array::DynamicArray;
use crate::{
    constants::{D_MESG, MAX_N, MAX_P},
    util::{
        coef::coef,
        random::get_random,
        ustr::{str32u, u16str, u32str, u8str},
    },
};
use core::marker::PhantomData;
use core::usize;

use super::definitions::LmotsPrivateKey;
use super::parameter::LmotsParameter;

#[allow(non_snake_case)]
#[derive(Debug)]
pub struct LmotsSignature<P: LmotsParameter> {
    pub C: DynamicArray<u8, MAX_N>,
    pub y: DynamicArray<DynamicArray<u8, MAX_N>, MAX_P>,
    lmots_parameter: PhantomData<P>,
}

impl<P: LmotsParameter> PartialEq for LmotsSignature<P> {
    fn eq(&self, other: &Self) -> bool {
        self.C == other.C && self.y == other.y && self.lmots_parameter == other.lmots_parameter
    }
}

impl<P: LmotsParameter> Eq for LmotsSignature<P> {}

impl<P: LmotsParameter> LmotsSignature<P> {
    #[allow(non_snake_case)]
    pub fn sign(private_key: &LmotsPrivateKey<P>, message: &[u8]) -> Self {
        let mut C = DynamicArray::new();

        let mut parameter = <P>::new();

        C.set_size(parameter.get_n() as usize);

        get_random(C.get_mut_slice());

        parameter.update(&private_key.I);
        parameter.update(&private_key.q);
        parameter.update(&D_MESG);
        parameter.update(&C.get_slice());
        parameter.update(message);

        let Q: DynamicArray<u8, MAX_N> = parameter.finalize_reset();
        let Q_and_checksum = parameter.get_appended_with_checksum(&Q.get_slice());

        let mut y: DynamicArray<DynamicArray<u8, MAX_N>, MAX_P> = DynamicArray::new();

        for i in 0..parameter.get_p() {
            let a = coef(
                &Q_and_checksum.get_slice(),
                i as u64,
                parameter.get_w() as u64,
            );
            let mut tmp = private_key.key[i as usize];
            for j in 0..a {
                parameter.update(&private_key.I);
                parameter.update(&private_key.q);
                parameter.update(&u16str(i));
                parameter.update(&u8str(j as u8));
                parameter.update(tmp.get_slice());
                tmp = parameter.finalize_reset();
            }
            y[i as usize] = tmp;
        }

        LmotsSignature {
            C,
            y,
            lmots_parameter: PhantomData,
        }
    }

    pub fn to_binary_representation(&self) -> DynamicArray<u8, { 4 + MAX_N + (MAX_N * MAX_P) }> {
        let mut result = DynamicArray::new();

        let parameter = <P>::new();

        result.append(&u32str(parameter.get_type()));
        result.append(self.C.get_slice());

        for x in self.y.into_iter() {
            for y in x.into_iter() {
                result.append(&[y]);
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

        let parameter = <P>::new();

        if !parameter.is_type_correct(lm_ots_type) {
            return None;
        }

        let n = parameter.get_n();
        let p = parameter.get_p();

        if data.len() != 4 + n as usize * (p as usize + 1) {
            return None;
        }

        let mut C = DynamicArray::new();

        C.append(&consumed_data[..n as usize]);
        consumed_data = &consumed_data[n as usize..];

        let mut y = DynamicArray::new();

        for i in 0..p {
            let mut temp = DynamicArray::new();
            temp.append(&consumed_data[..n as usize]);
            y[i as usize] = temp;

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

        let parameter = LmotsType::new();

        let mut c = DynamicArray::new();
        let mut y: DynamicArray<DynamicArray<u8, MAX_N>, MAX_P> = DynamicArray::new();

        for i in 0..parameter.get_n() as usize {
            c[i] = i as u8;
        }

        for i in 0..parameter.get_p() as usize {
            for j in 0..parameter.get_n() as usize {
                y[i][j] = j as u8;
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
