use tinyvec::ArrayVec;

use crate::{
    constants::{LmsLeafIdentifier, LmsTreeIdentifier, MAX_HASH_CHAIN_COUNT, MAX_HASH_SIZE},
    hasher::Hasher,
};

use super::parameters::LmotsParameter;

#[derive(Debug, PartialEq, Eq, Clone)]
pub struct LmotsPrivateKey<H: Hasher> {
    pub lms_tree_identifier: LmsTreeIdentifier,
    pub lms_leaf_identifier: LmsLeafIdentifier,
    pub key: ArrayVec<[ArrayVec<[u8; MAX_HASH_SIZE]>; MAX_HASH_CHAIN_COUNT]>, // [[0u8; n]; p];
    pub lmots_parameter: LmotsParameter<H>,
}

impl<H: Hasher> LmotsPrivateKey<H> {
    pub fn new(
        lms_tree_identifier: LmsTreeIdentifier,
        lms_leaf_identifier: LmsLeafIdentifier,
        key: ArrayVec<[ArrayVec<[u8; MAX_HASH_SIZE]>; MAX_HASH_CHAIN_COUNT]>,
        lmots_parameter: LmotsParameter<H>,
    ) -> Self {
        LmotsPrivateKey {
            lms_tree_identifier,
            lms_leaf_identifier,
            key,
            lmots_parameter,
        }
    }
}

pub struct LmotsPublicKey<H: Hasher> {
    pub lms_tree_identifier: LmsTreeIdentifier,
    pub lms_leaf_identifier: LmsLeafIdentifier,
    pub key: ArrayVec<[u8; MAX_HASH_SIZE]>,
    pub lmots_parameter: LmotsParameter<H>,
}

impl<H: Hasher> LmotsPublicKey<H> {
    pub fn new(
        lms_tree_identifier: LmsTreeIdentifier,
        lms_leaf_identifier: LmsLeafIdentifier,
        key: ArrayVec<[u8; MAX_HASH_SIZE]>,
        lmots_parameter: LmotsParameter<H>,
    ) -> Self {
        LmotsPublicKey {
            lms_tree_identifier,
            lms_leaf_identifier,
            key,
            lmots_parameter,
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::hasher::sha256::Sha256Hasher;
    use crate::lm_ots::parameters;

    macro_rules! generate_parameter_test {
        ($name:ident, $parameter:expr, $n:literal, $w:literal, $p:literal, $ls:literal, $type:literal) => {
            #[test]
            fn $name() {
                let parameter = $parameter.construct_parameter::<Sha256Hasher>().unwrap();
                assert_eq!(parameter.get_hash_function_output_size(), $n);
                assert_eq!(parameter.get_winternitz(), $w);
                assert_eq!(parameter.get_hash_chain_count(), $p);
                assert_eq!(parameter.get_checksum_left_shift(), $ls);
                assert_eq!(parameter.get_type_id(), $type);
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
