use crate::{
    constants::{
        lms_private_key_length, lms_public_key_length, lms_signature_length,
        MAX_HSS_PRIVATE_KEY_BINARY_REPRESENTATION_LENGTH, MAX_LMS_PUBLIC_KEY_LENGTH,
    },
    extract_or_return,
    hasher::Hasher,
    lms::{
        self,
        definitions::{LmsPrivateKey, LmsPublicKey},
        generate_key_pair,
        parameters::LmsParameter,
        signing::LmsSignature,
    },
    util::{
        dynamic_array::DynamicArray,
        helper::read_and_advance,
        ustr::{str32u, u32str},
    },
    LmotsParameter,
};

#[derive(Default, PartialEq)]
pub struct HssPrivateKey<H: Hasher, const L: usize> {
    pub private_key: DynamicArray<LmsPrivateKey<H>, L>,
    pub public_key: DynamicArray<LmsPublicKey<H>, L>,
    pub signatures: DynamicArray<LmsSignature<H>, L>, // Only L - 1 signatures needed
}

impl<H: Hasher, const L: usize> HssPrivateKey<H, L> {
    pub fn generate(
        lmots_parameter: LmotsParameter<H>,
        lms_parameter: LmsParameter<H>,
    ) -> Result<Self, &'static str> {
        let mut hss_private_key: HssPrivateKey<H, L> = Default::default();

        let lms_keypair = generate_key_pair(lmots_parameter, lms_parameter);

        hss_private_key.private_key.push(lms_keypair.private_key);
        hss_private_key.public_key.push(lms_keypair.public_key);

        for i in 1..L {
            let lms_keypair = generate_key_pair(lmots_parameter, lms_parameter);

            hss_private_key.private_key.push(lms_keypair.private_key);
            hss_private_key.public_key.push(lms_keypair.public_key);

            let signature = lms::signing::LmsSignature::sign(
                &mut hss_private_key.private_key[i - 1],
                hss_private_key.public_key[i]
                    .to_binary_representation()
                    .as_slice(),
            )?;

            hss_private_key.signatures.push(signature);
        }

        // TODO: Remove
        // Add dummy signature to first key generation such that the private key size stays always the same.
        // This prevents for passing in a too short slice when the private key gets updated
        let mut dummy_private_key = lms::generate_private_key(lmots_parameter, lms_parameter);
        let dummy_signature = lms::signing::LmsSignature::sign(&mut dummy_private_key, &[0])?;
        hss_private_key.signatures.push(dummy_signature);

        Ok(hss_private_key)
    }

    pub fn to_binary_representation(
        &self,
    ) -> DynamicArray<u8, MAX_HSS_PRIVATE_KEY_BINARY_REPRESENTATION_LENGTH> {
        let mut result = DynamicArray::new();

        for priv_key in self
            .private_key
            .iter()
            .map(|x| x.to_binary_representation())
        {
            result.append(priv_key.as_slice());
        }

        for pub_key in self.public_key.iter().map(|x| x.to_binary_representation()) {
            result.append(pub_key.as_slice());
        }

        for signatures in self.signatures.iter().map(|x| x.to_binary_representation()) {
            result.append(signatures.as_slice());
        }

        result
    }

    pub fn from_binary_representation(data: &[u8]) -> Option<Self> {
        let mut result: HssPrivateKey<H, L> = Default::default();

        let mut index = 0;

        for _ in 0..L {
            let private_key = extract_or_return!(
                lms::definitions::LmsPrivateKey::from_binary_representation(&data[index..])
            );
            result.private_key.push(private_key);
            index += lms_private_key_length();
        }

        for _ in 0..L {
            let public_key = extract_or_return!(
                lms::definitions::LmsPublicKey::from_binary_representation(&data[index..])
            );
            index += lms_public_key_length(public_key.lms_parameter.get_m());
            result.public_key.push(public_key);
        }

        // Only L-1 signatures are used
        for _ in 0..L {
            let signature = extract_or_return!(
                lms::signing::LmsSignature::from_binary_representation(&data[index..])
            );
            index += lms_signature_length(
                signature.lmots_signature.lmots_parameter.get_n(),
                signature.lmots_signature.lmots_parameter.get_p() as usize,
                signature.lms_parameter.get_m(),
                signature.lms_parameter.get_height() as usize,
            );
            result.signatures.push(signature);
        }

        Some(result)
    }

    pub fn get_public_key(&self) -> HssPublicKey<H, L> {
        HssPublicKey {
            public_key: self.public_key[0].clone(),
            level: L,
        }
    }
}

#[derive(PartialEq)]
pub struct HssPublicKey<H: Hasher, const L: usize> {
    pub public_key: LmsPublicKey<H>,
    pub level: usize,
}

impl<H: Hasher, const L: usize> HssPublicKey<H, L> {
    pub fn to_binary_representation(&self) -> DynamicArray<u8, { 4 + MAX_LMS_PUBLIC_KEY_LENGTH }> {
        let mut result = DynamicArray::new();

        result.append(&u32str(self.level as u32));
        result.append(self.public_key.to_binary_representation().as_slice());

        result
    }

    pub fn from_binary_representation(data: &[u8]) -> Option<Self> {
        let mut index = 0;

        let level = str32u(read_and_advance(data, 4, &mut index));

        let public_key = match LmsPublicKey::from_binary_representation(&data[index..]) {
            None => return None,
            Some(x) => x,
        };

        Some(Self {
            public_key,
            level: level as usize,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::{HssPrivateKey, HssPublicKey};
    use crate::hasher::sha256::Sha256Hasher;
    use crate::lm_ots::parameters::LmotsAlgorithm;
    use crate::lms::parameters::LmsAlgorithm;

    const LEVEL: usize = 3;

    #[test]
    fn test_public_key_binary_representation() {
        let public_key = crate::lms::generate_key_pair(
            LmotsAlgorithm::construct_default_parameter(),
            LmsAlgorithm::construct_default_parameter(),
        );
        let public_key: HssPublicKey<Sha256Hasher, 42> = HssPublicKey {
            level: 18,
            public_key: public_key.public_key,
        };

        let binary_representation = public_key.to_binary_representation();

        let deserialized: HssPublicKey<Sha256Hasher, 42> =
            HssPublicKey::from_binary_representation(binary_representation.as_slice())
                .expect("Deserialization should work.");

        assert!(public_key == deserialized);
    }

    #[test]
    fn test_private_key_binary_representation() {
        let private_key: HssPrivateKey<Sha256Hasher, LEVEL> = HssPrivateKey::generate(
            LmotsAlgorithm::construct_default_parameter(),
            LmsAlgorithm::construct_default_parameter(),
        )
        .expect("Should generate HSS keys");

        let serialized = private_key.to_binary_representation();
        let deserialized: HssPrivateKey<Sha256Hasher, LEVEL> =
            HssPrivateKey::from_binary_representation(serialized.as_slice())
                .expect("Should deserialize HSS private key");

        assert!(private_key == deserialized);
    }
}
