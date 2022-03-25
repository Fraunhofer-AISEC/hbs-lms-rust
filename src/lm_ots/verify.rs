use core::{marker::PhantomData, usize};

use tinyvec::ArrayVec;

use crate::lm_ots::parameters::LmotsParameter;
use crate::{constants::*, hasher::HashChain, util::coef::coef, LmotsAlgorithm};

use super::{definitions::LmotsPublicKey, signing::InMemoryLmotsSignature};

#[derive(Default)]
struct HashChainArray<H: HashChain> {
    pub array_w1: Option<ArrayVec<[ArrayVec<[u8; MAX_HASH_SIZE]>; HASH_CHAIN_COUNT_W1 as usize]>>,
    pub array_w2: Option<ArrayVec<[ArrayVec<[u8; MAX_HASH_SIZE]>; HASH_CHAIN_COUNT_W2 as usize]>>,
    pub array_w4: Option<ArrayVec<[ArrayVec<[u8; MAX_HASH_SIZE]>; HASH_CHAIN_COUNT_W4 as usize]>>,
    pub array_w8: Option<ArrayVec<[ArrayVec<[u8; MAX_HASH_SIZE]>; HASH_CHAIN_COUNT_W8 as usize]>>,
    phantom_data: PhantomData<H>,
}

impl<H: HashChain> HashChainArray<H> {
    pub fn new(lmots_parameter: &LmotsParameter<H>) -> Self {
        let mut hash_chain_array = HashChainArray::<H>::default();
        if LmotsAlgorithm::from(lmots_parameter.get_type_id()) == LmotsAlgorithm::LmotsW8 {
            hash_chain_array.array_w8 = Some(ArrayVec::<
                [ArrayVec<[u8; MAX_HASH_SIZE]>; HASH_CHAIN_COUNT_W8 as usize],
            >::default());
        } else if LmotsAlgorithm::from(lmots_parameter.get_type_id()) == LmotsAlgorithm::LmotsW4 {
            hash_chain_array.array_w4 = Some(ArrayVec::<
                [ArrayVec<[u8; MAX_HASH_SIZE]>; HASH_CHAIN_COUNT_W4 as usize],
            >::default());
        } else if LmotsAlgorithm::from(lmots_parameter.get_type_id()) == LmotsAlgorithm::LmotsW2 {
            hash_chain_array.array_w2 = Some(ArrayVec::<
                [ArrayVec<[u8; MAX_HASH_SIZE]>; HASH_CHAIN_COUNT_W2 as usize],
            >::default());
        } else {
            hash_chain_array.array_w1 = Some(ArrayVec::<
                [ArrayVec<[u8; MAX_HASH_SIZE]>; HASH_CHAIN_COUNT_W1 as usize],
            >::default());
        }
        hash_chain_array
    }

    pub fn push(&mut self, data: &ArrayVec<[u8; MAX_HASH_SIZE]>) {
        if let Some(array_w8) = &mut self.array_w8 {
            array_w8.push(*data);
        } else if let Some(array_w4) = &mut self.array_w4 {
            array_w4.push(*data);
        } else if let Some(array_w2) = &mut self.array_w2 {
            array_w2.push(*data);
        } else if let Some(array_w1) = &mut self.array_w1 {
            array_w1.push(*data);
        }
    }

    pub fn as_slice(&mut self) -> &[ArrayVec<[u8; MAX_HASH_SIZE]>] {
        if let Some(array_w8) = &self.array_w8 {
            array_w8.as_slice()
        } else if let Some(array_w4) = &self.array_w4 {
            array_w4.as_slice()
        } else if let Some(array_w2) = &self.array_w2 {
            array_w2.as_slice()
        } else {
            return self.array_w1.as_ref().unwrap().as_slice();
        }
    }
}

#[allow(dead_code)]
pub fn verify_signature_inmemory<'a, H: HashChain>(
    signature: &InMemoryLmotsSignature<'a, H>,
    public_key: &LmotsPublicKey<H>,
    message: &[u8],
) -> bool {
    if signature.lmots_parameter != public_key.lmots_parameter {
        return false;
    }

    let public_key_candidate = generate_public_key_candiate(
        signature,
        &public_key.lms_tree_identifier,
        u32::from_be_bytes(public_key.lms_leaf_identifier),
        message,
    );

    public_key_candidate == public_key.key
}

pub fn generate_public_key_candiate<'a, H: HashChain>(
    signature: &InMemoryLmotsSignature<'a, H>,
    lms_tree_identifier: &[u8],
    lms_leaf_identifier: u32,
    message: &[u8],
) -> ArrayVec<[u8; MAX_HASH_SIZE]> {
    let lmots_parameter = signature.lmots_parameter;
    let mut hasher = lmots_parameter.get_hasher();

    let lms_leaf_identifier = lms_leaf_identifier.to_be_bytes();

    hasher.update(lms_tree_identifier);
    hasher.update(&lms_leaf_identifier);
    hasher.update(&D_MESG);
    hasher.update(signature.signature_randomizer);
    hasher.update(message);

    let message_hash = hasher.finalize_reset();
    let message_hash_with_checksum = lmots_parameter.append_checksum_to(message_hash.as_slice());

    let mut hash_chain_array = HashChainArray::new(&lmots_parameter);
    let max_w = 2usize.pow(lmots_parameter.get_winternitz() as u32) - 1;

    for i in 0..lmots_parameter.get_hash_chain_count() {
        let a = coef(
            message_hash_with_checksum.as_slice(),
            i,
            lmots_parameter.get_winternitz(),
        ) as usize;

        let initial = signature.get_signature_data(i as usize);
        let mut hash_chain_data =
            H::prepare_hash_chain_data(lms_tree_identifier, &lms_leaf_identifier);
        let result = hasher.do_hash_chain(&mut hash_chain_data, i, initial, a, max_w);

        hash_chain_array.push(&result);
    }

    hasher.update(lms_tree_identifier);
    hasher.update(&lms_leaf_identifier);
    hasher.update(&D_PBLC);
    for hash_chain in hash_chain_array.as_slice() {
        hasher.update(hash_chain.as_slice());
    }
    hasher.finalize()
}

#[cfg(test)]
mod tests {
    use tinyvec::ArrayVec;

    use crate::constants::{LmsLeafIdentifier, LmsTreeIdentifier, Seed};
    use crate::hasher::sha256::Sha256;
    use crate::lm_ots::{
        definitions::LmotsPublicKey,
        keygen::{generate_private_key, generate_public_key},
        parameters,
        signing::{InMemoryLmotsSignature, LmotsSignature},
        verify::verify_signature_inmemory,
    };

    use rand::{rngs::OsRng, RngCore};

    macro_rules! generate_test {
        ($name:ident, $type:expr) => {
            #[test]
            fn $name() {
                let lms_tree_identifier: LmsTreeIdentifier = [2u8; 16];
                let lms_leaf_identifier: LmsLeafIdentifier = [0u8; 4];
                let seed: Seed = [
                    74, 222, 147, 88, 142, 55, 215, 148, 59, 52, 12, 170, 167, 93, 94, 237, 90,
                    176, 213, 104, 226, 71, 9, 74, 130, 187, 214, 75, 151, 184, 216, 175,
                ];

                let parameter = $type.construct_parameter::<Sha256>().unwrap();
                let private_key =
                    generate_private_key(lms_tree_identifier, lms_leaf_identifier, seed, parameter);
                let public_key: LmotsPublicKey<Sha256> = generate_public_key(&private_key);

                let mut message = [1, 3, 5, 9, 0];
                let mut signature_randomizer = ArrayVec::from([0u8; 32]);
                OsRng.fill_bytes(&mut signature_randomizer);

                let signature = LmotsSignature::sign(&private_key, &signature_randomizer, &message);

                let bin_representation = signature.to_binary_representation();

                let signature = InMemoryLmotsSignature::new(bin_representation.as_slice()).unwrap();

                assert!(verify_signature_inmemory(&signature, &public_key, &message) == true);

                message[0] = 5;
                assert!(verify_signature_inmemory(&signature, &public_key, &message) == false);
            }
        };
    }

    generate_test!(
        lmots_sha256_n32_w1_verify_test,
        parameters::LmotsAlgorithm::LmotsW1
    );

    generate_test!(
        lmots_sha256_n32_w2_verify_test,
        parameters::LmotsAlgorithm::LmotsW2
    );
    generate_test!(
        lmots_sha256_n32_w4_verify_test,
        parameters::LmotsAlgorithm::LmotsW4
    );
    generate_test!(
        lmots_sha256_n32_w8_verify_test,
        parameters::LmotsAlgorithm::LmotsW8
    );
}
