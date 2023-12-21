use tinyvec::ArrayVec;

use crate::constants::{D_INTR, D_LEAF, MAX_HASH_SIZE};
use crate::hasher::HashChain;
use crate::lm_ots;
use crate::util::helper::is_odd;

use super::definitions::InMemoryLmsPublicKey;
use super::signing::InMemoryLmsSignature;

pub fn verify<'a, H: HashChain>(
    signature: &InMemoryLmsSignature<'a, H>,
    public_key: &InMemoryLmsPublicKey<'a, H>,
    message: &[u8],
) -> Result<(), ()> {
    if signature.lmots_signature.lmots_parameter != public_key.lmots_parameter
        || signature.lms_parameter != public_key.lms_parameter
    {
        return Err(());
    }

    let public_key_canditate = generate_public_key_candidate(signature, public_key, message)?;

    if public_key_canditate.as_slice() == public_key.key {
        Ok(())
    } else {
        Err(())
    }
}

fn generate_public_key_candidate<'a, H: HashChain>(
    signature: &InMemoryLmsSignature<'a, H>,
    public_key: &InMemoryLmsPublicKey<'a, H>,
    message: &[u8],
) -> Result<ArrayVec<[u8; MAX_HASH_SIZE]>, ()> {
    let leafs = signature.lms_parameter.number_of_lm_ots_keys() as u32;

    let curr = signature.lms_leaf_identifier;
    if curr >= leafs {
        return Err(());
    }

    let ots_public_key_canditate = lm_ots::verify::generate_public_key_candidate(
        &signature.lmots_signature,
        public_key.lms_tree_identifier,
        signature.lms_leaf_identifier,
        message,
    );

    let mut node_num: u32 = leafs + signature.lms_leaf_identifier;
    let mut hasher = H::default();

    hasher.update(public_key.lms_tree_identifier);
    hasher.update(&node_num.to_be_bytes());
    hasher.update(&D_LEAF);
    hasher.update(ots_public_key_canditate.as_slice());
    let mut temp = hasher.finalize_reset();

    let mut i = 0;
    let mut nodes: [&[u8]; 2];

    while node_num > 1 {
        if is_odd(node_num as usize) {
            nodes = [signature.get_path(i), temp.as_slice()];
        } else {
            nodes = [temp.as_slice(), signature.get_path(i)];
        }

        i += 1;
        node_num /= 2;

        hasher.update(public_key.lms_tree_identifier);
        hasher.update(&node_num.to_be_bytes());
        hasher.update(&D_INTR);
        hasher.update(nodes[0]);
        hasher.update(nodes[1]);
        temp = hasher.finalize_reset();
    }

    Ok(temp)
}

#[cfg(test)]
mod tests {
    use crate::{
        lm_ots::parameters::LmotsAlgorithm,
        lms::{
            definitions::{InMemoryLmsPublicKey, LmsPrivateKey, LmsPublicKey},
            parameters::LmsAlgorithm,
            signing::{InMemoryLmsSignature, LmsSignature},
            SeedAndLmsTreeIdentifier,
        },
        Sha256_256,
    };

    use rand::{rngs::OsRng, RngCore};
    use tinyvec::ArrayVec;

    #[test]
    fn test_verification() {
        type Hasher = Sha256_256;

        let mut seed_and_lms_tree_identifier = SeedAndLmsTreeIdentifier::default();
        OsRng.fill_bytes(seed_and_lms_tree_identifier.seed.as_mut_slice());
        let mut private_key = LmsPrivateKey::new(
            seed_and_lms_tree_identifier.seed.clone(),
            seed_and_lms_tree_identifier.lms_tree_identifier,
            0,
            LmotsAlgorithm::construct_default_parameter(),
            LmsAlgorithm::construct_default_parameter(),
            None
        );

        let public_key = LmsPublicKey::new(&private_key, &mut None).to_binary_representation();

        let public_key = InMemoryLmsPublicKey::<Hasher>::new(public_key.as_slice()).unwrap();

        let mut first_message = [0u8, 4, 2, 7, 4, 2, 58, 3, 69, 3];
        let mut second_message = [1u8, 2, 3, 4, 5, 6, 7, 0];
        let mut signature_randomizer = ArrayVec::from([0u8; 32]);
        OsRng.fill_bytes(&mut signature_randomizer);

        let first_signature = LmsSignature::sign(
            &mut private_key,
            &first_message,
            &signature_randomizer,
            &mut None,
        )
        .unwrap()
        .to_binary_representation();
        let second_signature = LmsSignature::sign(
            &mut private_key,
            &second_message,
            &signature_randomizer,
            &mut None,
        )
        .unwrap()
        .to_binary_representation();

        let first_signature = InMemoryLmsSignature::new(first_signature.as_slice()).unwrap();
        let second_signature = InMemoryLmsSignature::new(second_signature.as_slice()).unwrap();

        assert!(super::verify(&first_signature, &public_key, &first_message).is_ok());
        first_message[5] = 13;
        assert!(super::verify(&first_signature, &public_key, &first_message).is_err());

        assert!(super::verify(&second_signature, &public_key, &second_message).is_ok());
        second_message[4] = 13;
        assert!(super::verify(&second_signature, &public_key, &second_message).is_err());
    }
}
