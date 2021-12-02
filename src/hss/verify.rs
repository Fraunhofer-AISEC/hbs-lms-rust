use crate::{
    hasher::Hasher,
    lms::{self},
};

use super::{definitions::InMemoryHssPublicKey, signing::InMemoryHssSignature};

pub fn verify<'a, H: Hasher>(
    signature: &InMemoryHssSignature<'a, H>,
    public_key: &InMemoryHssPublicKey<'a, H>,
    message: &[u8],
) -> Result<(), ()> {
    if signature.level + 1 != public_key.level {
        return Err(());
    }

    let mut key = &public_key.public_key;
    for i in 0..public_key.level - 1 {
        let sig = &signature.signed_public_keys[i].as_ref().unwrap().sig;
        let msg = &signature.signed_public_keys[i].as_ref().unwrap().public_key;

        if lms::verify::verify(sig, key, msg.as_slice()).is_err() {
            return Err(());
        }
        key = msg;
    }

    lms::verify::verify(&signature.signature, key, message)
}

#[cfg(test)]
mod tests {
    use crate::hasher::sha256::Sha256Hasher;
    use crate::hasher::Hasher;
    use crate::hss::definitions::HssPrivateKey;
    use crate::hss::definitions::HssPublicKey;
    use crate::hss::definitions::InMemoryHssPublicKey;
    use crate::hss::reference_impl_private_key::ReferenceImplPrivateKey;
    use crate::hss::signing::HssSignature;
    use crate::hss::signing::InMemoryHssSignature;
    use crate::hss::verify::verify;
    use crate::HssParameter;

    #[test]
    fn test_hss_verify() {
        let private_key = ReferenceImplPrivateKey::<Sha256Hasher>::generate(&[
            HssParameter::construct_default_parameters(),
            HssParameter::construct_default_parameters(),
        ])
        .unwrap();

        let mut private_key = HssPrivateKey::from(&private_key, None).unwrap();

        let public_key = private_key.get_public_key();

        let message_values = [42, 57, 20, 59, 33, 1, 49, 3, 99, 130, 50, 20];

        let mut message = [0u8; 64];
        message[..message_values.len()].copy_from_slice(&message_values);
        generate_signature_and_verify(&mut private_key, &public_key, &mut message);
    }

    fn generate_signature_and_verify<H: Hasher>(
        private_key: &mut HssPrivateKey<H>,
        public_key: &HssPublicKey<H>,
        message: &mut [u8],
    ) {
        let signature = if cfg!(feature = "fast_verify") {
            HssSignature::sign(private_key, None, Some(message)).expect("Should sign message")
        } else {
            HssSignature::sign(private_key, Some(message), None).expect("Should sign message")
        };

        let mem_sig = signature.to_binary_representation();
        let mem_sig = InMemoryHssSignature::<H>::new(mem_sig.as_slice()).unwrap();

        let mem_pub = public_key.to_binary_representation();
        let mem_pub = InMemoryHssPublicKey::new(mem_pub.as_slice()).unwrap();

        assert!(verify(&mem_sig, &mem_pub, message).is_ok());

        message[0] = !message[0];

        assert!(verify(&mem_sig, &mem_pub, message).is_err());
    }
}
