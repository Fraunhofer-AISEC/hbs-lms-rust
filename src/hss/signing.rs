use arrayvec::ArrayVec;

use crate::{
    constants::{
        lms_public_key_length, lms_signature_length, MAX_HSS_LEVELS, MAX_HSS_SIGNATURE_LENGTH,
        MAX_LMS_PUBLIC_KEY_LENGTH, MAX_LMS_SIGNATURE_LENGTH,
    },
    extract_or_return,
    hasher::Hasher,
    lms::{
        self,
        definitions::{InMemoryLmsPublicKey, LmsPublicKey},
        signing::{InMemoryLmsSignature, LmsSignature},
    },
    util::{
        helper::read_and_advance,
        ustr::{str32u, u32str},
    },
    LmotsAlgorithm, LmsAlgorithm,
};

use super::{definitions::HssPrivateKey, parameter::HssParameter};

#[derive(PartialEq)]
pub struct HssSignature<H: Hasher> {
    pub level: usize,
    pub signed_public_keys: ArrayVec<HssSignedPublicKey<H>, MAX_HSS_LEVELS>,
    pub signature: LmsSignature<H>,
}

/// To reduce memory footprint on verification we handle the signature in-memory using ```InMemoryHssSignature```.
/// In order to reduce complexity we use ```HssSignature``` for key generation and signature generation.
pub struct InMemoryHssSignature<'a, H: Hasher> {
    pub level: usize,
    pub signed_public_keys: ArrayVec<Option<InMemoryHssSignedPublicKey<'a, H>>, MAX_HSS_LEVELS>,
    pub signature: InMemoryLmsSignature<'a, H>,
}

impl<'a, H: Hasher> PartialEq<HssSignature<H>> for InMemoryHssSignature<'a, H> {
    fn eq(&self, other: &HssSignature<H>) -> bool {
        let first_condition = self.level == other.level && self.signature == other.signature;

        if !first_condition {
            return false;
        }

        for (x, y) in self
            .signed_public_keys
            .iter()
            .zip(other.signed_public_keys.iter())
        {
            if let Some(x) = x {
                if x != y {
                    return false;
                }
            } else {
                return false;
            }
        }

        true
    }
}

impl<H: Hasher> HssSignature<H> {
    pub fn sign(private_key: &mut HssPrivateKey<H>, message: &[u8]) -> Result<HssSignature<H>, ()> {
        let max_level = private_key.get_length();

        let lmots_parameter = private_key.private_key[0].lmots_parameter;
        let lms_parameter = private_key.private_key[0].lms_parameter;

        let parameter = HssParameter::new(
            LmotsAlgorithm::from(lmots_parameter.get_type_id()),
            LmsAlgorithm::from(lms_parameter.get_type()),
        );

        let prv = &mut private_key.private_key;
        let public = &mut private_key.public_key;
        let sig = &mut private_key.signatures;

        // Regenerate the keys if neccessary
        // Algorithm is heavily borrowed from RFC (https://datatracker.ietf.org/doc/html/rfc8554#section-6.2)

        // Start from lowest level tree and check if it is exhausted.
        // Stop if either a tree is not exhausted or we have reached the top level tree.
        let mut current_level = max_level;

        while prv[current_level - 1].used_leafs_index
            == 2u32.pow(prv[current_level - 1].lms_parameter.get_height() as u32)
        {
            current_level -= 1;
            if current_level == 0 {
                return Err(());
            }
        }

        // Then rebuild all the exhausted trees
        while current_level < max_level {
            let lms_key_pair = lms::generate_key_pair(&parameter);
            public[current_level] = lms_key_pair.public_key;
            prv[current_level] = lms_key_pair.private_key;

            let signature = lms::signing::LmsSignature::sign(
                &mut prv[current_level - 1],
                public[current_level].to_binary_representation().as_slice(),
            )?;
            sig[current_level - 1] = signature;
            current_level += 1;
        }

        // Sign the message
        let new_signature = lms::signing::LmsSignature::sign(&mut prv[max_level - 1], message)?;

        // Check if array already contains a signature at Index max_level - 1. If so replace it, otherwise push the new signature.
        if let Some(x) = sig.get_mut(max_level - 1) {
            *x = new_signature;
        } else {
            sig.push(new_signature);
        }

        let mut signed_public_keys = ArrayVec::new();

        // Create list of signed keys
        for i in 0..max_level - 1 {
            signed_public_keys.push(HssSignedPublicKey::new(
                sig[i].clone(),
                public[i + 1].clone(),
            ));
        }

        let signature = HssSignature {
            level: max_level - 1,
            signed_public_keys,
            signature: sig[max_level - 1].clone(),
        };

        Ok(signature)
    }

    pub fn to_binary_representation(&self) -> ArrayVec<u8, { MAX_HSS_SIGNATURE_LENGTH }> {
        let mut result = ArrayVec::new();

        result
            .try_extend_from_slice(&u32str(self.level as u32))
            .unwrap();

        for signed_public_key in self.signed_public_keys.iter() {
            let binary_representation = signed_public_key.to_binary_representation();
            result
                .try_extend_from_slice(binary_representation.as_slice())
                .unwrap();
        }

        result
            .try_extend_from_slice(self.signature.to_binary_representation().as_slice())
            .unwrap();

        result
    }
}

impl<'a, H: Hasher> InMemoryHssSignature<'a, H> {
    pub fn new(data: &'a [u8]) -> Option<Self> {
        let mut index = 0;

        let level = str32u(read_and_advance(data, 4, &mut index)) as usize;

        let mut signed_public_keys = ArrayVec::new();

        for _ in 0..level {
            let signed_public_key =
                extract_or_return!(InMemoryHssSignedPublicKey::<'a, H>::new(&data[index..]));
            index += signed_public_key.len();
            signed_public_keys.push(Some(signed_public_key));
        }

        let signature = match InMemoryLmsSignature::<'a, H>::new(&data[index..]) {
            None => return None,
            Some(x) => x,
        };

        Some(Self {
            level,
            signed_public_keys,
            signature,
        })
    }
}

#[derive(Default, Clone, PartialEq)]
pub struct HssSignedPublicKey<H: Hasher> {
    pub sig: LmsSignature<H>,
    pub public_key: LmsPublicKey<H>,
}

#[derive(Clone)]
pub struct InMemoryHssSignedPublicKey<'a, H: Hasher> {
    pub sig: InMemoryLmsSignature<'a, H>,
    pub public_key: InMemoryLmsPublicKey<'a, H>,
}

impl<'a, H: Hasher> PartialEq<HssSignedPublicKey<H>> for InMemoryHssSignedPublicKey<'a, H> {
    fn eq(&self, other: &HssSignedPublicKey<H>) -> bool {
        self.sig == other.sig && self.public_key == other.public_key
    }
}

impl<H: Hasher> HssSignedPublicKey<H> {
    pub fn new(signature: LmsSignature<H>, public_key: LmsPublicKey<H>) -> Self {
        Self {
            sig: signature,
            public_key,
        }
    }

    pub fn to_binary_representation(
        &self,
    ) -> ArrayVec<u8, { MAX_LMS_SIGNATURE_LENGTH + MAX_LMS_PUBLIC_KEY_LENGTH }> {
        let mut result = ArrayVec::new();

        result
            .try_extend_from_slice(self.sig.to_binary_representation().as_slice())
            .unwrap();
        result
            .try_extend_from_slice(self.public_key.to_binary_representation().as_slice())
            .unwrap();

        result
    }
}

impl<'a, H: Hasher> InMemoryHssSignedPublicKey<'a, H> {
    pub fn new(data: &'a [u8]) -> Option<Self> {
        let sig = match InMemoryLmsSignature::new(data) {
            None => return None,
            Some(x) => x,
        };

        let sig_size = lms_signature_length(
            sig.lmots_signature.lmots_parameter.get_hash_function_output_size(),
            sig.lmots_signature.lmots_parameter.get_max_hash_iterations() as usize,
            sig.lms_parameter.get_m(),
            sig.lms_parameter.get_height() as usize,
        );

        let public_key = match InMemoryLmsPublicKey::new(&data[sig_size..]) {
            None => return None,
            Some(x) => x,
        };

        Some(Self { sig, public_key })
    }

    pub fn len(&self) -> usize {
        let sig = &self.sig;
        let sig_size = lms_signature_length(
            sig.lmots_signature.lmots_parameter.get_hash_function_output_size(),
            sig.lmots_signature.lmots_parameter.get_max_hash_iterations() as usize,
            sig.lms_parameter.get_m(),
            sig.lms_parameter.get_height() as usize,
        );
        let public_key_size = lms_public_key_length(sig.lms_parameter.get_m());

        sig_size + public_key_size
    }
}

#[cfg(test)]
mod tests {
    use crate::hasher::sha256::Sha256Hasher;
    use crate::hss::reference_impl_private_key::ReferenceImplPrivateKey;
    use crate::hss::signing::InMemoryHssSignature;
    use crate::hss::signing::InMemoryHssSignedPublicKey;
    use crate::lms::signing::LmsSignature;
    use crate::HssParameter;

    use super::HssPrivateKey;
    use super::HssSignature;
    use super::HssSignedPublicKey;

    #[test]
    fn test_signed_public_key_binary_representation() {
        let mut keypair =
            crate::lms::generate_key_pair(&HssParameter::construct_default_parameters());

        let message = [3, 54, 32, 45, 67, 32, 12, 58, 29, 49];
        let signature =
            LmsSignature::sign(&mut keypair.private_key, &message).expect("Signing should work");

        let signed_public_key = HssSignedPublicKey {
            public_key: keypair.public_key,
            sig: signature,
        };

        let binary_representation = signed_public_key.to_binary_representation();
        let deserialized = InMemoryHssSignedPublicKey::new(binary_representation.as_slice())
            .expect("Deserialization should work.");

        assert!(deserialized == signed_public_key);
    }

    #[test]
    fn test_hss_signature_binary_representation() {
        let private_key = ReferenceImplPrivateKey::<Sha256Hasher>::generate(&[
            HssParameter::construct_default_parameters(),
            HssParameter::construct_default_parameters(),
        ])
        .unwrap();

        let mut private_key = HssPrivateKey::from(&private_key, None).unwrap();

        let message = [2, 56, 123, 22, 42, 49, 22];

        let signature =
            HssSignature::sign(&mut private_key, &message).expect("Should generate HSS signature");

        let binary_representation = signature.to_binary_representation();
        let deserialized =
            InMemoryHssSignature::<Sha256Hasher>::new(binary_representation.as_slice())
                .expect("Deserialization should work.");

        assert!(deserialized == signature);
    }
}
