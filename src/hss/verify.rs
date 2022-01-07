use crate::{
    hasher::HashChain,
    lms::{self},
};

use super::{definitions::InMemoryHssPublicKey, signing::InMemoryHssSignature};

pub fn verify<'a, H: HashChain>(
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
    use crate::{
        hasher::{sha256::Sha256, HashChain},
        hss::{
            definitions::{HssPrivateKey, HssPublicKey, InMemoryHssPublicKey},
            reference_impl_private_key::ReferenceImplPrivateKey,
            signing::{HssSignature, InMemoryHssSignature},
            verify::verify,
        },
        HssParameter, Seed,
    };

    use rand::{rngs::OsRng, RngCore};

    #[test]
    fn test_hss_verify() {
        let mut seed = Seed::default();
        OsRng.fill_bytes(&mut seed);
        let rfc_key = ReferenceImplPrivateKey::<Sha256>::generate(
            &[
                HssParameter::construct_default_parameters(),
                HssParameter::construct_default_parameters(),
            ],
            &seed,
        )
        .unwrap();

        let mut private_key = HssPrivateKey::from(&rfc_key).unwrap();
        let public_key = HssPublicKey::from(&rfc_key, None).unwrap();

        let message_values = [42, 57, 20, 59, 33, 1, 49, 3, 99, 130, 50, 20];

        let mut message = [0u8; 64];
        message[..message_values.len()].copy_from_slice(&message_values);
        generate_signature_and_verify(&mut private_key, &public_key, &mut message);
    }

    fn generate_signature_and_verify<H: HashChain>(
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
