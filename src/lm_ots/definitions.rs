use crate::{
    constants::{IType, QType, MAX_N, MAX_P},
    hasher::Hasher,
    util::dynamic_array::DynamicArray,
};

use super::parameters::LmotsParameter;

#[allow(non_snake_case)]
#[derive(Debug, PartialEq, Eq, Clone)]
pub struct LmotsPrivateKey<H: Hasher> {
    pub I: IType,
    pub q: QType,
    pub key: DynamicArray<DynamicArray<u8, MAX_N>, MAX_P>, // [[0u8; n]; p];
    pub lmots_parameter: LmotsParameter<H>,
}

#[allow(non_snake_case)]
impl<H: Hasher> LmotsPrivateKey<H> {
    pub fn new(
        I: IType,
        q: QType,
        key: DynamicArray<DynamicArray<u8, MAX_N>, MAX_P>,
        lmots_parameter: LmotsParameter<H>,
    ) -> Self {
        LmotsPrivateKey {
            I,
            q,
            key,
            lmots_parameter,
        }
    }
}

#[allow(non_snake_case)]
pub struct LmotsPublicKey<H: Hasher> {
    pub I: IType,
    pub q: QType,
    pub key: DynamicArray<u8, MAX_N>,
    lmots_parameter: LmotsParameter<H>,
}

#[allow(non_snake_case)]
impl<H: Hasher> LmotsPublicKey<H> {
    pub fn new(
        I: IType,
        q: QType,
        key: DynamicArray<u8, MAX_N>,
        lmots_parameter: LmotsParameter<H>,
    ) -> Self {
        LmotsPublicKey {
            I,
            q,
            key,
            lmots_parameter,
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::lm_ots::{parameter, parameters};
    use crate::hasher::sha256::Sha256Hasher;

    macro_rules! generate_parameter_test {
        ($name:ident, $parameter:expr, $n:literal, $w:literal, $p:literal, $ls:literal, $type:literal) => {
            #[test]
            fn $name() {
                let parameter = $parameter.construct_parameter::<Sha256Hasher>().unwrap();
                assert_eq!(parameter.get_n(), $n);
                assert_eq!(parameter.get_winternitz(), $w);
                assert_eq!(parameter.get_p(), $p);
                assert_eq!(parameter.get_ls(), $ls);
                assert_eq!(parameter.get_type(), $type);
            }
        };
    }

    generate_parameter_test!(
        lmots_sha256_n32_w1_parameter_test,
        parameters::LmotsAlgorithm::LmotsW1,
        32,
        1,
        265,
        7,
        1
    );
    generate_parameter_test!(
        lmots_sha256_n32_w2_parameter_test,
        parameters::LmotsAlgorithm::LmotsW2,
        32,
        2,
        133,
        6,
        2
    );
    generate_parameter_test!(
        lmots_sha256_n32_w4_parameter_test,
        parameters::LmotsAlgorithm::LmotsW4,
        32,
        4,
        67,
        4,
        3
    );
    generate_parameter_test!(
        lmots_sha256_n32_w8_parameter_test,
        parameters::LmotsAlgorithm::LmotsW8,
        32,
        8,
        34,
        0,
        4
    );
}
