use core::usize;

use crate::{
    constants::*,
    util::{coef::coef, dynamic_array::DynamicArray},
};

use super::{definitions::LmotsPublicKey, parameter::LmotsParameter, signing::LmotsSignature};

#[allow(non_snake_case)]
#[allow(dead_code)]
pub fn verify_signature<OTS: LmotsParameter>(
    signature: &LmotsSignature<OTS>,
    public_key: &LmotsPublicKey<OTS>,
    message: &[u8],
) -> bool {
    let public_key_candidate =
        generate_public_key_canditate(signature, &public_key.I, &public_key.q, message);

    public_key_candidate == public_key.key
}

#[allow(non_snake_case)]
pub fn generate_public_key_canditate<OTS: LmotsParameter>(
    signature: &LmotsSignature<OTS>,
    I: &IType,
    q: &QType,
    message: &[u8],
) -> DynamicArray<u8, MAX_N> {
    let mut hasher = <OTS>::get_hasher();

    hasher.update(I);
    hasher.update(q);
    hasher.update(&D_MESG);
    hasher.update(signature.C.get_slice());
    hasher.update(message);

    let Q = hasher.finalize_reset();
    let Q_and_checksum = <OTS>::get_appended_with_checksum(Q.get_slice());

    let mut z: DynamicArray<DynamicArray<u8, MAX_N>, MAX_P> = DynamicArray::new();
    let max_w = 2usize.pow(<OTS>::W as u32) - 1;

    for i in 0..<OTS>::get_p() {
        let a = coef(&Q_and_checksum.get_slice(), i as u64, <OTS>::W as u64) as usize;
        let mut tmp = signature.y[i as usize];

        hasher.do_hash_chain(&I, &q, i, a, max_w, tmp.get_mut_slice());

        z[i as usize] = tmp;
    }

    hasher.update(I);
    hasher.update(q);
    hasher.update(&D_PBLC);

    for item in z.into_iter() {
        hasher.update(item.get_slice());
    }

    hasher.finalize()
}

#[cfg(test)]
mod tests {
    use crate::constants::*;
    use crate::lm_ots::{
        definitions::LmotsPublicKey,
        keygen::{generate_private_key, generate_public_key},
        parameter,
        signing::LmotsSignature,
        verify::verify_signature,
    };

    macro_rules! generate_test {
        ($name:ident, $type:ty) => {
            #[test]
            fn $name() {
                let i: IType = [2u8; 16];
                let q: QType = [0u8; 4];
                let seed: Seed = [
                    74, 222, 147, 88, 142, 55, 215, 148, 59, 52, 12, 170, 167, 93, 94, 237, 90,
                    176, 213, 104, 226, 71, 9, 74, 130, 187, 214, 75, 151, 184, 216, 175,
                ];

                let private_key = generate_private_key(i, q, seed);
                let public_key: LmotsPublicKey<$type> = generate_public_key(&private_key);

                let mut message = [1, 3, 5, 9, 0];

                let signature = LmotsSignature::sign(&private_key, &message);

                assert!(verify_signature(&signature, &public_key, &message) == true);

                message[0] = 5;
                assert!(verify_signature(&signature, &public_key, &message) == false);
            }
        };
    }

    generate_test!(lmots_sha256_n32_w1_verify_test, parameter::LmotsSha256N32W1);

    generate_test!(lmots_sha256_n32_w2_verify_test, parameter::LmotsSha256N32W2);
    generate_test!(lmots_sha256_n32_w4_verify_test, parameter::LmotsSha256N32W4);
    generate_test!(lmots_sha256_n32_w8_verify_test, parameter::LmotsSha256N32W8);
}
