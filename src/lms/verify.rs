use crate::definitions::D_INTR;
use crate::definitions::D_LEAF;
use crate::lms::definitions::LmsPublicKey;
use crate::lms::signing::LmsSignature;
use crate::util::helper::is_odd;
use crate::util::ustr::str32u;
use crate::util::ustr::u32str;

pub fn verify(
    signature: &LmsSignature,
    public_key: &LmsPublicKey,
    message: &[u8],
) -> Result<(), &'static str> {
    let public_key_canditate = generate_public_key_candiate(signature, public_key, message)?;
    // let public_key = public_key.tree[1].clone();

    if public_key_canditate == public_key.key {
        Ok(())
    } else {
        Err("Public key canditate is not equal to public key.")
    }
}

fn generate_public_key_candiate(
    signature: &LmsSignature,
    public_key: &LmsPublicKey,
    message: &[u8],
) -> Result<Vec<u8>, &'static str> {
    if signature.lmots_signature.parameter._type != public_key.lm_ots_type {
        return Err("LM OTS Signature parameter type does not match public key signature type.");
    }

    if signature.lms_parameter._type != public_key.lms_type {
        return Err("LMS Signature does not match public key signature type.");
    }

    let leafs = 2u32.pow(signature.lms_parameter.h.into());
    if str32u(&signature.q) >= leafs {
        return Err("q is larger than the maximum number of private keys.");
    }

    let ots_public_key_canditate = crate::lm_ots::verify::generate_public_key_canditate(
        &signature.lmots_signature,
        &public_key.I,
        &signature.q,
        message,
    );

    let mut node_num = leafs + str32u(&signature.q);
    let mut hasher = signature.lms_parameter.get_hasher();

    hasher.update(&public_key.I);
    hasher.update(&u32str(node_num));
    hasher.update(&D_LEAF);
    hasher.update(&ots_public_key_canditate);

    let mut temp = hasher.finalize_reset();
    let mut i = 0;

    while node_num > 1 {
        hasher.update(&public_key.I);
        hasher.update(&u32str(node_num / 2));
        hasher.update(&D_INTR);

        if is_odd(node_num as usize) {
            hasher.update(&signature.path[i]);
            hasher.update(&temp);
        } else {
            hasher.update(&temp);
            hasher.update(&signature.path[i]);
        }
        temp = hasher.finalize_reset();
        node_num /= 2;
        i += 1;
    }

    Ok(temp)
}

#[cfg(test)]
mod tests {

    use super::*;
    use crate::lms::signing::*;
    use crate::lms::*;

    #[test]
    fn test_verification() {
        let mut private_key = generate_private_key(
            crate::lms::definitions::LmsAlgorithmType::LmsSha256M32H5,
            crate::lm_ots::definitions::LmotsAlgorithmType::LmotsSha256N32W1,
        );
        let public_key = generate_public_key(&private_key);

        let mut first_message: Vec<u8> = vec![0, 4, 2, 7, 4, 2, 58, 3, 69, 3];
        let mut second_message: Vec<u8> = vec![1, 2, 3, 4, 5, 6, 7, 0];

        let first_signature =
            LmsSignature::sign(&mut private_key, &public_key, &first_message).unwrap();
        let second_signature =
            LmsSignature::sign(&mut private_key, &public_key, &second_message).unwrap();

        assert!(verify(&first_signature, &public_key, &first_message).is_ok());
        first_message[5] = 13;
        assert!(verify(&first_signature, &public_key, &first_message).is_err());

        assert!(verify(&second_signature, &public_key, &second_message).is_ok());
        second_message[4] = 13;
        assert!(verify(&second_signature, &public_key, &second_message).is_err());
    }
}
