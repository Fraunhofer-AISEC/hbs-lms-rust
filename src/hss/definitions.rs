use crate::lms::{
    self,
    definitions::{LmsPrivateKey, LmsPublicKey},
    generate_key_pair_with_seed,
    signing::LmsSignature,
};
use crate::{
    constants::{MAX_HSS_LEVELS, MAX_LMS_PUBLIC_KEY_LENGTH},
    hasher::Hasher,
    util::{
        dynamic_array::DynamicArray,
        helper::read_and_advance,
        ustr::{str32u, u32str},
    },
};

use super::rfc_private_key::generate_child_seed_I_value;
use super::rfc_private_key::RfcPrivateKey;

#[derive(Default, PartialEq)]
pub struct HssPrivateKey<H: Hasher> {
    pub private_key: DynamicArray<LmsPrivateKey<H>, MAX_HSS_LEVELS>,
    pub public_key: DynamicArray<LmsPublicKey<H>, MAX_HSS_LEVELS>,
    pub signatures: DynamicArray<LmsSignature<H>, MAX_HSS_LEVELS>, // Only L - 1 signatures needed
}

impl<H: Hasher> HssPrivateKey<H> {
    pub fn get_l(&self) -> usize {
        self.private_key.len()
    }

    pub fn from(private_key: &RfcPrivateKey<H>) -> Result<Self, &'static str> {
        let mut hss_private_key: HssPrivateKey<H> = Default::default();

        let parameters = private_key.compressed_parameter.to();

        let mut current_seed = private_key.generate_root_seed_I_value();

        let lms_keypair = generate_key_pair_with_seed(&current_seed, &parameters[0]);

        hss_private_key.private_key.push(lms_keypair.private_key);
        hss_private_key.public_key.push(lms_keypair.public_key);

        for i in 1..parameters.len() {
            let parameter = if parameters.len() == 1 {
                &parameters[0]
            } else {
                &parameters[i]
            };

            current_seed = generate_child_seed_I_value(&current_seed, i as u32);

            let lms_keypair = generate_key_pair_with_seed(&current_seed, parameter);

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
        let mut dummy_private_key = lms::keygen::generate_private_key(
            *parameters[0].get_lmots_parameter(),
            *parameters[0].get_lms_parameter(),
        );
        let dummy_signature = lms::signing::LmsSignature::sign(&mut dummy_private_key, &[0])?;
        hss_private_key.signatures.push(dummy_signature);

        Ok(hss_private_key)
    }

    pub fn get_public_key(&self) -> HssPublicKey<H> {
        HssPublicKey {
            public_key: self.public_key[0].clone(),
            level: self.get_l(),
        }
    }
}

#[derive(PartialEq)]
pub struct HssPublicKey<H: Hasher> {
    pub public_key: LmsPublicKey<H>,
    pub level: usize,
}

impl<H: Hasher> HssPublicKey<H> {
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
    use super::HssPublicKey;
    use crate::hasher::sha256::Sha256Hasher;
    use crate::HssParameter;

    #[test]
    fn test_public_key_binary_representation() {
        let public_key =
            crate::lms::generate_key_pair(&HssParameter::construct_default_parameters());
        let public_key: HssPublicKey<Sha256Hasher> = HssPublicKey {
            level: 18,
            public_key: public_key.public_key,
        };

        let binary_representation = public_key.to_binary_representation();

        let deserialized: HssPublicKey<Sha256Hasher> =
            HssPublicKey::from_binary_representation(binary_representation.as_slice())
                .expect("Deserialization should work.");

        assert!(public_key == deserialized);
    }
}
