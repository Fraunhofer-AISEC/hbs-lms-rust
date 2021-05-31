use crate::{
    definitions::{D_MESG, D_PBLC},
    util::{
        coef::coef,
        ustr::{u16str, u8str},
    },
};

use super::{
    definitions::{IType, LmotsPublicKey, QType},
    signing::LmotsSignature,
};

#[allow(non_snake_case)]
pub fn verify_signature(
    signature: &LmotsSignature,
    public_key: &LmotsPublicKey,
    message: &[u8],
) -> bool {
    let public_key_candiatte =
        generate_public_key_canditate(signature, &public_key.I, &public_key.q, message);

    public_key_candiatte == public_key.key
}

#[allow(non_snake_case)]
pub fn generate_public_key_canditate(
    signature: &LmotsSignature,
    I: &IType,
    q: &QType,
    message: &[u8],
) -> Vec<u8> {
    let mut hasher = signature.parameter.get_hasher();

    hasher.update(I);
    hasher.update(q);
    hasher.update(&D_MESG);
    hasher.update(&signature.C);
    hasher.update(message);

    let Q = hasher.finalize_reset();
    let Q_checksum = signature.parameter.checksum(&Q);

    let mut Q_and_checksum = Q;
    Q_and_checksum.push((Q_checksum >> 8 & 0xff) as u8);
    Q_and_checksum.push((Q_checksum & 0xff) as u8);

    let mut z = vec![vec![0u8; signature.parameter.n as usize]; signature.parameter.p as usize];
    for i in 0..signature.parameter.p {
        let a = coef(&&Q_and_checksum, i as u64, signature.parameter.w as u64);
        let mut tmp = signature.y[i as usize].clone();
        let max_w = 2u64.pow(signature.parameter.w as u32) - 1;

        for j in a..max_w {
            hasher.update(I);
            hasher.update(q);
            hasher.update(&u16str(i));
            hasher.update(&u8str(j as u8));
            hasher.update(&tmp);
            tmp = hasher.finalize_reset();
        }
        z[i as usize] = tmp;
    }

    hasher.update(I);
    hasher.update(q);
    hasher.update(&D_PBLC);

    for item in z {
        hasher.update(&item);
    }

    hasher.finalize()
}

#[cfg(test)]
mod tests {
    use crate::lm_ots::{
        definitions::{IType, QType},
        keygen::{generate_private_key, generate_public_key},
        signing::LmotsSignature,
        verify::verify_signature,
    };

    macro_rules! generate_test {
        ($name:ident, $type:expr) => {
            #[test]
            fn $name() {
                let i: IType = [2u8; 16];
                let q: QType = [2u8; 4];

                let private_key = generate_private_key(i, q, $type);
                let public_key = generate_public_key(&private_key);

                let mut message: Vec<u8> = vec![1, 3, 5, 9, 0];

                let signature = LmotsSignature::sign(&private_key, &message);

                assert!(verify_signature(&signature, &public_key, &message) == true);

                message[0] = 5;
                assert!(verify_signature(&signature, &public_key, &message) == false);
            }
        };
    }

    generate_test!(
        lmots_sha256_n32_w1_verify_test,
        crate::lm_ots::definitions::LmotsAlgorithmType::LmotsSha256N32W1
    );
    generate_test!(
        lmots_sha256_n32_w2_verify_test,
        crate::lm_ots::definitions::LmotsAlgorithmType::LmotsSha256N32W2
    );
    generate_test!(
        lmots_sha256_n32_w4_verify_test,
        crate::lm_ots::definitions::LmotsAlgorithmType::LmotsSha256N32W4
    );
    generate_test!(
        lmots_sha256_n32_w8_verify_test,
        crate::lm_ots::definitions::LmotsAlgorithmType::LmotsSha256N32W8
    );
}
