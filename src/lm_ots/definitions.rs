use core::marker::PhantomData;

use crate::{
    constants::{MAX_N, MAX_P},
    util::dynamic_array::DynamicArray,
};

use super::parameter::LmotsParameter;

pub type IType = [u8; 16];
pub type QType = [u8; 4];
pub type Seed = [u8; 32];

#[allow(non_snake_case)]
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub struct LmotsPrivateKey<OTS: LmotsParameter> {
    pub I: IType,
    pub q: QType,
    pub key: DynamicArray<DynamicArray<u8, MAX_N>, MAX_P>, // [[0u8; n]; p];
    lmots_parameter: PhantomData<OTS>,
}

#[allow(non_snake_case)]
impl<OTS: LmotsParameter> LmotsPrivateKey<OTS> {
    pub fn new(I: IType, q: QType, key: DynamicArray<DynamicArray<u8, MAX_N>, MAX_P>) -> Self {
        LmotsPrivateKey {
            I,
            q,
            key,
            lmots_parameter: PhantomData,
        }
    }
}

#[allow(non_snake_case)]
pub struct LmotsPublicKey<OTS: LmotsParameter> {
    pub I: IType,
    pub q: QType,
    pub key: DynamicArray<u8, MAX_N>,
    lmots_parameter: PhantomData<OTS>,
}

#[allow(non_snake_case)]
impl<OTS: LmotsParameter> LmotsPublicKey<OTS> {
    pub fn new(I: IType, q: QType, key: DynamicArray<u8, MAX_N>) -> Self {
        LmotsPublicKey {
            I,
            q,
            key,
            lmots_parameter: PhantomData,
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::lm_ots::parameter;

    use super::*;

    macro_rules! generate_parameter_test {
        ($name:ident, $parameter:ty, $n:literal, $w:literal, $p:literal, $ls:literal, $type:literal) => {
            #[test]
            fn $name() {
                assert_eq!(<$parameter>::N, $n);
                assert_eq!(<$parameter>::W, $w);
                assert_eq!(<$parameter>::get_p(), $p);
                assert_eq!(<$parameter>::get_ls(), $ls);
                assert_eq!(<$parameter>::TYPE, $type);
            }
        };
    }

    generate_parameter_test!(
        lmots_sha256_n32_w1_parameter_test,
        parameter::LmotsSha256N32W1,
        32,
        1,
        265,
        7,
        1
    );
    generate_parameter_test!(
        lmots_sha256_n32_w2_parameter_test,
        parameter::LmotsSha256N32W2,
        32,
        2,
        133,
        6,
        2
    );
    generate_parameter_test!(
        lmots_sha256_n32_w4_parameter_test,
        parameter::LmotsSha256N32W4,
        32,
        4,
        67,
        4,
        3
    );
    generate_parameter_test!(
        lmots_sha256_n32_w8_parameter_test,
        parameter::LmotsSha256N32W8,
        32,
        8,
        34,
        0,
        4
    );
}
