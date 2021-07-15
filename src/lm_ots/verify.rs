use core::usize;

use crate::{
    constants::*,
    hasher::Hasher,
    util::{coef::coef, dynamic_array::DynamicArray},
};

use super::{definitions::LmotsPublicKey, signing::LmotsSignature};

#[allow(non_snake_case)]
#[allow(dead_code)]
pub fn verify_signature<H: Hasher>(
    signature: &LmotsSignature<H>,
    public_key: &LmotsPublicKey<H>,
    message: &[u8],
) -> bool {
    if signature.lmots_parameter != public_key.lmots_parameter {
        return false;
    }

    let public_key_candidate =
        generate_public_key_canditate(signature, &public_key.I, &public_key.q, message);

    public_key_candidate == public_key.key
}

#[allow(non_snake_case)]
pub fn generate_public_key_canditate<H: Hasher>(
    signature: &LmotsSignature<H>,
    I: &IType,
    q: &QType,
    message: &[u8],
) -> DynamicArray<u8, MAX_HASH> {
    let lmots_parameter = signature.lmots_parameter;
    let mut hasher = lmots_parameter.get_hasher();

    hasher.update(I);
    hasher.update(q);
    hasher.update(&D_MESG);
    hasher.update(signature.C.as_slice());
    hasher.update(message);

    let Q = hasher.finalize_reset();
    let Q_and_checksum = lmots_parameter.get_appended_with_checksum(Q.as_slice());

    let mut z: DynamicArray<DynamicArray<u8, MAX_HASH>, MAX_P> = DynamicArray::new();
    let max_w = 2usize.pow(lmots_parameter.get_winternitz() as u32) - 1;

    for i in 0..lmots_parameter.get_p() {
        let a = coef(
            &Q_and_checksum.as_slice(),
            i as u64,
            lmots_parameter.get_winternitz() as u64,
        ) as usize;
        let mut tmp = signature.y[i as usize].clone();

        hasher.do_hash_chain(&I, &q, i, a, max_w, tmp.as_mut_slice());

        z.push(tmp);
    }

    hasher.update(I);
    hasher.update(q);
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
        signing::LmotsSignature,
        verify::verify_signature,
    };

    macro_rules! generate_test {
        ($name:ident, $type:expr) => {
            #[test]
            fn $name() {
                let i: IType = [2u8; 16];
                let q: QType = [0u8; 4];
                let seed: Seed = [
                    74, 222, 147, 88, 142, 55, 215, 148, 59, 52, 12, 170, 167, 93, 94, 237, 90,
                    176, 213, 104, 226, 71, 9, 74, 130, 187, 214, 75, 151, 184, 216, 175,
                ];

                let parameter = $type.construct_parameter::<Sha256Hasher>().unwrap();
                let private_key = generate_private_key(i, q, seed, parameter);
                let public_key: LmotsPublicKey<Sha256Hasher> = generate_public_key(&private_key);

                let mut message = [1, 3, 5, 9, 0];

                let signature = LmotsSignature::sign(&private_key, &message);

                assert!(verify_signature(&signature, &public_key, &message) == true);

                message[0] = 5;
                assert!(verify_signature(&signature, &public_key, &message) == false);
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
