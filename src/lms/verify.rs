use crate::constants::D_INTR;
use crate::constants::D_LEAF;
use crate::constants::MAX_HASH;
use crate::hasher::Hasher;
use crate::lms::definitions::LmsPublicKey;
use crate::lms::signing::LmsSignature;
use crate::util::dynamic_array::DynamicArray;
use crate::util::helper::is_odd;
use crate::util::ustr::str32u;
use crate::util::ustr::u32str;

pub fn verify<H: Hasher>(
    signature: &LmsSignature<H>,
    public_key: &LmsPublicKey<H>,
    message: &[u8],
) -> Result<(), &'static str> {
    if signature.lmots_signature.lmots_parameter != public_key.lmots_parameter
        || signature.lms_parameter != public_key.lms_parameter
    {
        return Err("Signature parameter and public key parameter do not match.");
    }

    let public_key_canditate = generate_public_key_candiate(signature, public_key, message)?;

    if public_key_canditate == public_key.key {
        Ok(())
    } else {
        Err("Public key canditate is not equal to public key.")
    }
}

fn generate_public_key_candiate<H: Hasher>(
    signature: &LmsSignature<H>,
    public_key: &LmsPublicKey<H>,
    message: &[u8],
) -> Result<DynamicArray<u8, MAX_HASH>, &'static str> {
    let mut hasher = <H>::get_hasher();

    let leafs = signature.lms_parameter.number_of_lm_ots_keys() as u32;

    let curr = str32u(&signature.q);
    if curr >= leafs {
        return Err("q is larger than the maximum number of private keys.");
    }

    let ots_public_key_canditate = crate::lm_ots::verify::generate_public_key_canditate(
        &signature.lmots_signature,
        &public_key.I,
        &signature.q,
        message,
    );

    let mut node_num = leafs + str32u(&signature.q);

    hasher.update(&public_key.I);
    hasher.update(&u32str(node_num));
    hasher.update(&D_LEAF);
    hasher.update(ots_public_key_canditate.as_slice());

    let mut temp = hasher.finalize_reset();
    let mut i = 0;

    while node_num > 1 {
        hasher.update(&public_key.I);
        hasher.update(&u32str(node_num / 2));
        hasher.update(&D_INTR);

        if is_odd(node_num as usize) {
            hasher.update(&signature.path[i].as_slice());
            hasher.update(&temp.as_slice());
        } else {
            hasher.update(&temp.as_slice());
            hasher.update(&signature.path[i].as_slice());
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
            keygen::{generate_private_key, generate_public_key},
            parameters::LmsAlgorithm,
            signing::LmsSignature,
        },
    };

    #[test]
    fn test_verification() {
        let mut private_key = generate_private_key(
            LmotsAlgorithm::construct_default_parameter(),
            LmsAlgorithm::construct_default_parameter(),
        );

        let public_key = generate_public_key(&private_key, &mut None);

        let mut first_message = [0u8, 4, 2, 7, 4, 2, 58, 3, 69, 3];
        let mut second_message = [1u8, 2, 3, 4, 5, 6, 7, 0];

        let first_signature = LmsSignature::sign(&mut private_key, &first_message).unwrap();
        let second_signature = LmsSignature::sign(&mut private_key, &second_message).unwrap();

        assert!(super::verify(&first_signature, &public_key, &first_message).is_ok());
        first_message[5] = 13;
        assert!(super::verify(&first_signature, &public_key, &first_message).is_err());

        assert!(super::verify(&second_signature, &public_key, &second_message).is_ok());
        second_message[4] = 13;
        assert!(super::verify(&second_signature, &public_key, &second_message).is_err());
    }
}
