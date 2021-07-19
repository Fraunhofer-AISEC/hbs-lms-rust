use crate::{
    constants::{
        lms_public_key_length, lms_signature_length, MAX_HSS_LEVELS, MAX_HSS_SIGNATURE_LENGTH,
        MAX_LMS_PUBLIC_KEY_LENGTH, MAX_LMS_SIGNATURE_LENGTH,
    },
    extract_or_return,
    hasher::Hasher,
    lms::{self, definitions::LmsPublicKey, signing::LmsSignature},
    util::{
        dynamic_array::DynamicArray,
        helper::read_and_advance,
        ustr::{str32u, u32str},
    },
};

use super::{definitions::HssPrivateKey, parameter::HssParameter};

#[derive(PartialEq)]
pub struct HssSignature<H: Hasher> {
    pub level: usize,
    pub signed_public_keys: DynamicArray<HssSignedPublicKey<H>, MAX_HSS_LEVELS>,
    pub signature: LmsSignature<H>,
}

impl<H: Hasher> HssSignature<H> {
    pub fn sign(
        private_key: &mut HssPrivateKey<H>,
        message: &[u8],
    ) -> Result<HssSignature<H>, &'static str> {
        let l = private_key.get_length();

        let lmots_parameter = private_key.private_key[0].lmots_parameter;
        let lms_parameter = private_key.private_key[0].lms_parameter;

        let parameter = HssParameter::new(lmots_parameter, lms_parameter);

        let prv = &mut private_key.private_key;
        let public = &mut private_key.public_key;
        let sig = &mut private_key.signatures;

        // Regenerate the keys if neccessary
        let mut d = l;

        while prv[d - 1].q == 2u32.pow(prv[d - 1].lms_parameter.get_height() as u32) {
            d -= 1;
            if d == 0 {
                return Err("All keys are exhausted.");
            }
        }

        while d < l {
            let lms_key_pair = lms::generate_key_pair(&parameter);
            public[d] = lms_key_pair.public_key;
            prv[d] = lms_key_pair.private_key;

            let signature = lms::signing::LmsSignature::sign(
                &mut prv[d - 1],
                public[d].to_binary_representation().as_slice(),
            )?;
            sig[d - 1] = signature;
            d += 1;
        }

        // Sign the message
        sig[l - 1] = lms::signing::LmsSignature::sign(&mut prv[l - 1], message)?;

        let mut signed_public_keys = DynamicArray::new();

        // Create list of signed keys
        for i in 0..l - 1 {
            signed_public_keys.push(HssSignedPublicKey::new(
                sig[i].clone(),
                public[i + 1].clone(),
            ));
        }

        let signature = HssSignature {
            level: l - 1,
            signed_public_keys,
            signature: sig[l - 1].clone(),
        };

        Ok(signature)
    }

    pub fn to_binary_representation(&self) -> DynamicArray<u8, { MAX_HSS_SIGNATURE_LENGTH }> {
        let mut result = DynamicArray::new();

        result.append(&u32str(self.level as u32));

        for signed_public_key in self.signed_public_keys.iter() {
            let binary_representation = signed_public_key.to_binary_representation();
            result.append(binary_representation.as_slice());
        }

        result.append(self.signature.to_binary_representation().as_slice());

        result
    }

    pub fn from_binary_representation(data: &[u8]) -> Option<Self> {
        let mut index = 0;

        let level = str32u(read_and_advance(data, 4, &mut index));

        let mut signed_public_keys = DynamicArray::new();

        for _ in 0..level {
            let signed_public_key = extract_or_return!(
                HssSignedPublicKey::from_binary_representation(&data[index..])
            );
            index += signed_public_key.len();
            signed_public_keys.push(signed_public_key);
        }

        let signature = match LmsSignature::from_binary_representation(&data[index..]) {
            None => return None,
            Some(x) => x,
        };

        Some(Self {
            level: level as usize,
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

impl<H: Hasher> HssSignedPublicKey<H> {
    pub fn new(signature: LmsSignature<H>, public_key: LmsPublicKey<H>) -> Self {
        Self {
            sig: signature,
            public_key,
        }
    }

    pub fn to_binary_representation(
        &self,
    ) -> DynamicArray<u8, { MAX_LMS_SIGNATURE_LENGTH + MAX_LMS_PUBLIC_KEY_LENGTH }> {
        let mut result = DynamicArray::new();

        result.append(self.sig.to_binary_representation().as_slice());
        result.append(self.public_key.to_binary_representation().as_slice());

        result
    }

    pub fn from_binary_representation(data: &[u8]) -> Option<Self> {
        let sig = match LmsSignature::from_binary_representation(data) {
            None => return None,
            Some(x) => x,
        };

        let sig_size = lms_signature_length(
            sig.lmots_signature.lmots_parameter.get_n(),
            sig.lmots_signature.lmots_parameter.get_p() as usize,
            sig.lms_parameter.get_m(),
            sig.lms_parameter.get_height() as usize,
        );

        let public_key = match LmsPublicKey::from_binary_representation(&data[sig_size..]) {
            None => return None,
            Some(x) => x,
        };

        Some(Self { sig, public_key })
    }

    pub fn len(&self) -> usize {
        let sig = &self.sig;
        let sig_size = lms_signature_length(
            sig.lmots_signature.lmots_parameter.get_n(),
            sig.lmots_signature.lmots_parameter.get_p() as usize,
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
    use crate::hss::rfc_private_key::RfcPrivateKey;
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
        let deserialized =
            HssSignedPublicKey::from_binary_representation(binary_representation.as_slice())
                .expect("Deserialization should work.");

        assert!(signed_public_key == deserialized);
    }

    #[test]
    fn test_hss_signature_binary_representation() {
        let private_key = RfcPrivateKey::<Sha256Hasher>::generate(&[
            HssParameter::construct_default_parameters(),
            HssParameter::construct_default_parameters(),
        ])
        .unwrap();

        let mut private_key = HssPrivateKey::from(&private_key, None).unwrap();

        let message = [2, 56, 123, 22, 42, 49, 22];

        let signature =
            HssSignature::sign(&mut private_key, &message).expect("Should generate HSS signature");

        let binary_representation = signature.to_binary_representation();
        let deserialized = HssSignature::<Sha256Hasher>::from_binary_representation(
            binary_representation.as_slice(),
        )
        .expect("Deserialization should work.");

        assert!(signature == deserialized);
    }
}
