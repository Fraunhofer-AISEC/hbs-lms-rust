use tinyvec::TinyVec;

use crate::{
    constants::{LmsLeafIdentifier, LmsTreeIdentifier, MAX_HASH_CHAIN_COUNT, MAX_HASH_SIZE},
    hasher::HashChain,
};

use super::parameters::LmotsParameter;

#[derive(Debug, PartialEq, Eq, Clone)]
pub struct LmotsPrivateKey<H: HashChain> {
    pub lms_tree_identifier: LmsTreeIdentifier,
    pub lms_leaf_identifier: LmsLeafIdentifier,
    pub key: TinyVec<[TinyVec<[u8; MAX_HASH_SIZE]>; MAX_HASH_CHAIN_COUNT]>, // [[0u8; n]; p];
    pub lmots_parameter: LmotsParameter<H>,
}

impl<H: HashChain> LmotsPrivateKey<H> {
    pub fn new(
        lms_tree_identifier: LmsTreeIdentifier,
        lms_leaf_identifier: LmsLeafIdentifier,
        key: TinyVec<[TinyVec<[u8; MAX_HASH_SIZE]>; MAX_HASH_CHAIN_COUNT]>,
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

pub struct LmotsPublicKey<H: HashChain> {
    pub lms_tree_identifier: LmsTreeIdentifier,
    pub lms_leaf_identifier: LmsLeafIdentifier,
    pub key: TinyVec<[u8; MAX_HASH_SIZE]>,
    pub lmots_parameter: LmotsParameter<H>,
}

impl<H: HashChain> LmotsPublicKey<H> {
    pub fn new(
        lms_tree_identifier: LmsTreeIdentifier,
        lms_leaf_identifier: LmsLeafIdentifier,
        key: TinyVec<[u8; MAX_HASH_SIZE]>,
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
    use crate::hasher::sha256::{Sha256_128, Sha256_192, Sha256_256};
    use crate::lm_ots::parameters;

    macro_rules! generate_parameter_test {
        ($name:ident, $parameter:expr, $hash_chain:ty, $n:literal, $w:literal, $p:literal, $ls:literal, $type:literal) => {
            #[test]
            fn $name() {
                let parameter = $parameter.construct_parameter::<$hash_chain>().unwrap();
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
        Sha256_256,
        32,
        1,
        265,
        7,
        1
    );
    generate_parameter_test!(
        lmots_sha256_n24_w1_parameter_test,
        parameters::LmotsAlgorithm::LmotsW1,
        Sha256_192,
        24,
        1,
        200,
        7,
        1
    );
    generate_parameter_test!(
        lmots_sha256_n16_w1_parameter_test,
        parameters::LmotsAlgorithm::LmotsW1,
        Sha256_128,
        16,
        1,
        136,
        7,
        1
    );
    generate_parameter_test!(
        lmots_sha256_n32_w2_parameter_test,
        parameters::LmotsAlgorithm::LmotsW2,
        Sha256_256,
        32,
        2,
        133,
        6,
        2
    );
    generate_parameter_test!(
        lmots_sha256_n24_w2_parameter_test,
        parameters::LmotsAlgorithm::LmotsW2,
        Sha256_192,
        24,
        2,
        101,
        6,
        2
    );
    generate_parameter_test!(
        lmots_sha256_n16_w2_parameter_test,
        parameters::LmotsAlgorithm::LmotsW2,
        Sha256_128,
        16,
        2,
        68,
        6,
        2
    );
    generate_parameter_test!(
        lmots_sha256_n32_w4_parameter_test,
        parameters::LmotsAlgorithm::LmotsW4,
        Sha256_256,
        32,
        4,
        67,
        4,
        3
    );
    generate_parameter_test!(
        lmots_sha256_n24_w4_parameter_test,
        parameters::LmotsAlgorithm::LmotsW4,
        Sha256_192,
        24,
        4,
        51,
        4,
        3
    );
    generate_parameter_test!(
        lmots_sha256_n16_w4_parameter_test,
        parameters::LmotsAlgorithm::LmotsW4,
        Sha256_128,
        16,
        4,
        35,
        4,
        3
    );
    generate_parameter_test!(
        lmots_sha256_n32_w8_parameter_test,
        parameters::LmotsAlgorithm::LmotsW8,
        Sha256_256,
        32,
        8,
        34,
        0,
        4
    );
    generate_parameter_test!(
        lmots_sha256_n24_w8_parameter_test,
        parameters::LmotsAlgorithm::LmotsW8,
        Sha256_192,
        24,
        8,
        26,
        0,
        4
    );
    generate_parameter_test!(
        lmots_sha256_n16_w8_parameter_test,
        parameters::LmotsAlgorithm::LmotsW8,
        Sha256_128,
        16,
        8,
        18,
        0,
        4
    );
}
