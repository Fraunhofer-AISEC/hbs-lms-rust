pub mod definitions;
pub mod signing;
pub mod verify;

use crate::{
    constants::{
        MAX_HSS_PRIVATE_KEY_BINARY_REPRESENTATION_LENGTH, MAX_HSS_SIGNATURE_LENGTH, MAX_M,
    },
    extract_or, extract_or_return,
    hss::definitions::HssPublicKey,
    util::dynamic_array::DynamicArray,
    LmotsParameter, LmsParameter,
};

use self::{definitions::HssPrivateKey, signing::HssSignature};

pub struct HssBinaryData {
    pub public_key: DynamicArray<u8, { 4 + 4 + 4 + 16 + MAX_M }>,
    pub private_key: DynamicArray<u8, MAX_HSS_PRIVATE_KEY_BINARY_REPRESENTATION_LENGTH>,
}

pub fn hss_verify<OTS: LmotsParameter, LMS: LmsParameter, const L: usize>(
    message: &[u8],
    signature: &[u8],
    public_key: &[u8],
) -> bool {
    let signature: HssSignature<OTS, LMS, L> =
        extract_or!(HssSignature::from_binary_representation(signature), false);
    let public_key: HssPublicKey<OTS, LMS, L> =
        extract_or!(HssPublicKey::from_binary_representation(public_key), false);

    crate::hss::verify::verify(&signature, &public_key, &message).is_ok()
}

pub fn hss_sign<OTS: LmotsParameter, LMS: LmsParameter, const L: usize>(
    message: &[u8],
    private_key: &mut [u8],
) -> Option<DynamicArray<u8, MAX_HSS_SIGNATURE_LENGTH>> {
    let mut parsed_private_key: HssPrivateKey<OTS, LMS, L> =
        extract_or_return!(HssPrivateKey::from_binary_representation(private_key));

    let signature = match HssSignature::sign(&mut parsed_private_key, &message) {
        Err(_) => return None,
        Ok(x) => x,
    };

    // Overwrite advanced private key
    // private_key.clear();
    // private_key.append(parsed_private_key.to_binary_representation().as_slice());
    private_key.copy_from_slice(parsed_private_key.to_binary_representation().as_slice());

    Some(signature.to_binary_representation())
}

pub fn hss_keygen<OTS: LmotsParameter, LMS: LmsParameter, const L: usize>() -> Option<HssBinaryData>
{
    let hss_key: HssPrivateKey<OTS, LMS, L> =
        match crate::hss::definitions::HssPrivateKey::generate() {
            Err(_) => return None,
            Ok(x) => x,
        };

    Some(HssBinaryData {
        private_key: hss_key.to_binary_representation(),
        public_key: hss_key.get_public_key().to_binary_representation(),
    })
}

#[cfg(test)]
mod tests {

    use crate::lm_ots;
    use crate::lms;

    use super::*;

    #[test]
    fn test_signing() {
        type LmotsType = lm_ots::parameter::LmotsSha256N32W2;
        type LmsType = lms::parameter::LmsSha256M32H5;
        const LEVEL: usize = 3;

        let mut keys = hss_keygen::<LmotsType, LmsType, LEVEL>().expect("Should generate HSS keys");

        let mut message = [
            32u8, 48, 2, 1, 48, 58, 20, 57, 9, 83, 99, 255, 0, 34, 2, 1, 0,
        ];

        let signature =
            hss_sign::<LmotsType, LmsType, LEVEL>(&message, keys.private_key.as_mut_slice())
                .expect("Signing should complete without error.");

        assert!(hss_verify::<LmotsType, LmsType, LEVEL>(
            &message,
            signature.as_slice(),
            keys.public_key.as_slice()
        ));

        message[0] = 33;

        assert!(
            hss_verify::<LmotsType, LmsType, LEVEL>(
                &message,
                signature.as_slice(),
                keys.public_key.as_slice()
            ) == false
        );
    }
}
