pub mod aux;
pub mod definitions;
pub mod parameter;
pub mod rfc_private_key;
mod seed_derive;
pub mod signing;
pub mod verify;

use crate::{
    constants::{MAX_HASH, MAX_HSS_SIGNATURE_LENGTH, RFC_PRIVATE_KEY_SIZE},
    extract_or, extract_or_return,
    hasher::Hasher,
    hss::definitions::HssPublicKey,
    util::dynamic_array::DynamicArray,
};

use self::{
    definitions::HssPrivateKey, parameter::HssParameter, rfc_private_key::RfcPrivateKey,
    signing::HssSignature,
};

pub struct HssBinaryData {
    pub public_key: DynamicArray<u8, { 4 + 4 + 4 + 16 + MAX_HASH }>,
    pub private_key: DynamicArray<u8, RFC_PRIVATE_KEY_SIZE>,
}

pub fn hss_verify<H: Hasher>(message: &[u8], signature: &[u8], public_key: &[u8]) -> bool {
    let signature: HssSignature<H> =
        extract_or!(HssSignature::from_binary_representation(signature), false);
    let public_key: HssPublicKey<H> =
        extract_or!(HssPublicKey::from_binary_representation(public_key), false);

    crate::hss::verify::verify(&signature, &public_key, &message).is_ok()
}

pub fn hss_sign<H: Hasher>(
    message: &[u8],
    private_key: &mut [u8],
) -> Option<DynamicArray<u8, MAX_HSS_SIGNATURE_LENGTH>> {
    let mut rfc_private_key =
        extract_or_return!(RfcPrivateKey::from_binary_representation(&private_key));

    let mut parsed_private_key: HssPrivateKey<H> = match HssPrivateKey::from(&rfc_private_key, None)
    {
        Ok(x) => x,
        Err(_) => return None,
    };

    let signature = match HssSignature::sign(&mut parsed_private_key, &message) {
        Err(_) => return None,
        Ok(x) => x,
    };

    // Overwrite advanced private key
    // TODO: HssPrivateKey should not be existent
    rfc_private_key.q += 1;
    private_key.copy_from_slice(rfc_private_key.to_binary_representation().as_slice());

    Some(signature.to_binary_representation())
}

pub fn hss_keygen<H: Hasher>(
    parameters: &[HssParameter<H>],
    seed: Option<&[u8]>,
    aux_data: Option<&mut &mut [u8]>,
) -> Option<HssBinaryData> {
    let private_key = if let Some(seed) = seed {
        RfcPrivateKey::generate_with_seed(parameters, seed)
    } else {
        RfcPrivateKey::generate(parameters)
    };

    if let Some(private_key) = private_key {
        let hss_key: HssPrivateKey<H> = match HssPrivateKey::from(&private_key, aux_data) {
            Err(_) => return None,
            Ok(x) => x,
        };
        Some(HssBinaryData {
            private_key: private_key.to_binary_representation(),
            public_key: hss_key.get_public_key().to_binary_representation(),
        })
    } else {
        None
    }
}

#[cfg(test)]
mod tests {

    use crate::hasher::sha256::Sha256Hasher;

    use super::*;

    #[test]
    fn test_signing() {
        type H = Sha256Hasher;

        let mut keys = hss_keygen::<H>(
            &[
                HssParameter::construct_default_parameters(),
                HssParameter::construct_default_parameters(),
                HssParameter::construct_default_parameters(),
            ],
            None,
            None,
        )
        .expect("Should generate HSS keys");

        let mut message = [
            32u8, 48, 2, 1, 48, 58, 20, 57, 9, 83, 99, 255, 0, 34, 2, 1, 0,
        ];

        let signature = hss_sign::<H>(&message, keys.private_key.as_mut_slice())
            .expect("Signing should complete without error.");

        assert!(hss_verify::<H>(
            &message,
            signature.as_slice(),
            keys.public_key.as_slice()
        ));

        message[0] = 33;

        assert!(
            hss_verify::<H>(&message, signature.as_slice(), keys.public_key.as_slice()) == false
        );
    }
}
