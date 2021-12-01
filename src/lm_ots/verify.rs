use core::usize;

use arrayvec::ArrayVec;

use crate::{
    constants::*,
    hasher::Hasher,
    util::{
        coef::coef,
        ustr::{str32u, u32str},
    },
};

use super::{definitions::LmotsPublicKey, signing::InMemoryLmotsSignature};

#[allow(dead_code)]
pub fn verify_signature_inmemory<'a, H: Hasher>(
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
        str32u(&public_key.lms_leaf_identifier[..]),
        message,
    );

    public_key_candidate == public_key.key
}

pub fn generate_public_key_candiate<'a, H: Hasher>(
    signature: &InMemoryLmotsSignature<'a, H>,
    lms_tree_identifier: &[u8],
    lms_leaf_identifier: u32,
    message: &[u8],
) -> ArrayVec<u8, MAX_HASH_SIZE> {
    let lmots_parameter = signature.lmots_parameter;
    let mut hasher = lmots_parameter.get_hasher();

    let lms_leaf_identifier = u32str(lms_leaf_identifier);

    hasher.update(lms_tree_identifier);
    hasher.update(&lms_leaf_identifier);
    hasher.update(&D_MESG);
    hasher.update(signature.signature_randomizer);
    hasher.update(message);

    let message_hash = hasher.finalize_reset();
    let message_hash_with_checksum = lmots_parameter.append_checksum_to(message_hash.as_slice());

    let mut z: ArrayVec<ArrayVec<u8, MAX_HASH_SIZE>, MAX_HASH_CHAIN_ITERATIONS> = ArrayVec::new();
    let max_w = 2usize.pow(lmots_parameter.get_winternitz() as u32) - 1;

    for i in 0..lmots_parameter.get_max_hash_iterations() {
        let a = coef(
            message_hash_with_checksum.as_slice(),
            i,
            lmots_parameter.get_winternitz(),
        ) as usize;

        let initial = signature.get_signature_data(i as usize);
        let mut hash_chain_data =
            H::prepare_hash_chain_data(lms_tree_identifier, &lms_leaf_identifier);
        let result = hasher.do_hash_chain(&mut hash_chain_data, i, initial, a, max_w);

        z.push(result);
    }

    hasher.update(lms_tree_identifier);
    hasher.update(&lms_leaf_identifier);
    hasher.update(&D_PBLC);

    for item in z.into_iter() {
        hasher.update(item.as_slice());
    }

    hasher.finalize()
}

#[cfg(test)]
mod tests {
    use crate::constants::*;
    use crate::hasher::sha256::Sha256Hasher;
    use crate::lm_ots::parameters;
    use crate::lm_ots::{
        definitions::LmotsPublicKey,
        keygen::{generate_private_key, generate_public_key},
        signing::{InMemoryLmotsSignature, LmotsSignature},
        verify::verify_signature_inmemory,
    };

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

                let parameter = $type.construct_parameter::<Sha256Hasher>().unwrap();
                let private_key =
                    generate_private_key(lms_tree_identifier, lms_leaf_identifier, seed, parameter);
                let public_key: LmotsPublicKey<Sha256Hasher> = generate_public_key(&private_key);

                let mut message = [1, 3, 5, 9, 0];

                let signature = LmotsSignature::sign(&private_key, None, &message);

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
