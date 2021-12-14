use crate::constants::D_INTR;
use crate::constants::D_LEAF;
use crate::constants::MAX_HASH_SIZE;
use crate::hasher::Hasher;
use crate::util::helper::is_odd;
use crate::util::ustr::u32str;
use tinyvec::ArrayVec;

use super::definitions::InMemoryLmsPublicKey;
use super::signing::InMemoryLmsSignature;

pub fn verify<'a, H: Hasher>(
    signature: &InMemoryLmsSignature<'a, H>,
    public_key: &InMemoryLmsPublicKey<'a, H>,
    message: &[u8],
) -> Result<(), ()> {
    if signature.lmots_signature.lmots_parameter != public_key.lmots_parameter
        || signature.lms_parameter != public_key.lms_parameter
    {
        return Err(());
    }

    let public_key_canditate = generate_public_key_candiate(signature, public_key, message)?;

    if public_key_canditate.as_slice() == public_key.key {
        Ok(())
    } else {
        Err(())
    }
}

fn generate_public_key_candiate<'a, H: Hasher>(
    signature: &InMemoryLmsSignature<'a, H>,
    public_key: &InMemoryLmsPublicKey<'a, H>,
    message: &[u8],
) -> Result<ArrayVec<[u8; MAX_HASH_SIZE]>, ()> {
    let leafs = signature.lms_parameter.number_of_lm_ots_keys() as u32;

    let curr = signature.lms_leaf_identifier;
    if curr >= leafs {
        return Err(());
    }

    let ots_public_key_canditate = crate::lm_ots::verify::generate_public_key_candiate(
        &signature.lmots_signature,
        public_key.lms_tree_identifier,
        signature.lms_leaf_identifier,
        message,
    );

    let mut node_num = leafs + signature.lms_leaf_identifier;

    let mut hasher = <H>::get_hasher();
    hasher.update(public_key.lms_tree_identifier);
    hasher.update(&u32str(node_num));
    hasher.update(&D_LEAF);
    hasher.update(ots_public_key_canditate.as_slice());

    let mut temp = hasher.finalize_reset();
    let mut i = 0;

    while node_num > 1 {
        hasher.update(public_key.lms_tree_identifier);
        hasher.update(&u32str(node_num / 2));
        hasher.update(&D_INTR);

        if is_odd(node_num as usize) {
            hasher.update(signature.get_path(i));
            hasher.update(temp.as_slice());
        } else {
            hasher.update(temp.as_slice());
            hasher.update(signature.get_path(i));
        }
        temp = hasher.finalize_reset();
        node_num /= 2;
        i += 1;
    }

    Ok(temp)
}

#[cfg(test)]
mod tests {
    use crate::{
        lm_ots::parameters::LmotsAlgorithm,
        lms::{
            definitions::InMemoryLmsPublicKey,
            keygen::{generate_private_key, generate_public_key},
            parameters::LmsAlgorithm,
            signing::{InMemoryLmsSignature, LmsSignature},
        },
        Sha256Hasher,
    };

    #[test]
    fn test_verification() {
        type Hasher = Sha256Hasher;

        let mut private_key = generate_private_key(
            LmotsAlgorithm::construct_default_parameter(),
            LmsAlgorithm::construct_default_parameter(),
        );

        let public_key = generate_public_key(&private_key, &mut None).to_binary_representation();

        let public_key = InMemoryLmsPublicKey::<Hasher>::new(public_key.as_slice()).unwrap();

        let mut first_message = [0u8, 4, 2, 7, 4, 2, 58, 3, 69, 3];
        let mut second_message = [1u8, 2, 3, 4, 5, 6, 7, 0];

        let first_signature = LmsSignature::sign(&mut private_key, &first_message, None)
            .unwrap()
            .to_binary_representation();
        let second_signature = LmsSignature::sign(&mut private_key, &second_message, None)
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
