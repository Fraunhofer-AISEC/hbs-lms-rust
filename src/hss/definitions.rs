use crate::{
    constants::{
        MAX_HSS_PRIVATE_KEY_BINARY_REPRESENTATION_LENGTH, MAX_HSS_PRIVATE_KEY_LENGTH,
        MAX_LMS_PUBLIC_KEY_LENGTH,
    },
    lms::{
        self,
        definitions::{LmsPrivateKey, LmsPublicKey},
        generate_key_pair,
        signing::LmsSignature,
    },
    util::{
        dynamic_array::DynamicArray,
        helper::read_and_advance,
        ustr::{str32u, u32str},
    },
    LmotsParameter, LmsParameter,
};

#[derive(Default)]
pub struct HssPrivateKey<OTS: LmotsParameter, LMS: LmsParameter, const L: usize> {
    pub private_key: DynamicArray<LmsPrivateKey<OTS, LMS>, L>,
    pub public_key: DynamicArray<LmsPublicKey<OTS, LMS>, L>,
    pub signatures: DynamicArray<LmsSignature<OTS, LMS>, L>, // Only L - 1 signatures needed
}

impl<OTS: LmotsParameter, LMS: LmsParameter, const L: usize> HssPrivateKey<OTS, LMS, L> {
    fn generate() -> Result<Self, &'static str> {
        let mut hss_private_key: HssPrivateKey<OTS, LMS, L> = Default::default();

        let lms_keypair = generate_key_pair();

        hss_private_key.private_key.push(lms_keypair.private_key);
        hss_private_key.public_key.push(lms_keypair.public_key);

        for i in 1..L {
            let lms_keypair = generate_key_pair();

            hss_private_key.private_key.push(lms_keypair.private_key);
            hss_private_key.public_key.push(lms_keypair.public_key);

            let signature = lms::signing::LmsSignature::sign(
                &mut hss_private_key.private_key[i],
                hss_private_key.public_key[i]
                    .to_binary_representation()
                    .as_slice(),
            )?;

            hss_private_key.signatures.push(signature);
        }

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

    pub fn get_public_key(&self) -> HssPublicKey<OTS, LMS, L> {
        HssPublicKey {
            public_key: self.public_key[0].clone(),
            level: L,
        }
    }
}

#[derive(PartialEq)]
pub struct HssPublicKey<OTS: LmotsParameter, LMS: LmsParameter, const L: usize> {
    pub public_key: LmsPublicKey<OTS, LMS>,
    pub level: usize,
}

impl<OTS: LmotsParameter, LMS: LmsParameter, const L: usize> HssPublicKey<OTS, LMS, L> {
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
    use crate::lm_ots::parameter::*;
    use crate::lms::parameter::*;

    type OTS = LmotsSha256N32W2;
    type LMS = LmsSha256M32H5;

    #[test]
    fn test_public_key_binary_representation() {
        let public_key = crate::lms::generate_key_pair::<OTS, LMS>();
        let public_key: HssPublicKey<OTS, LMS, 42> = HssPublicKey {
            level: 18,
            public_key: public_key.public_key,
        };

        let binary_representation = public_key.to_binary_representation();

        let deserialized: HssPublicKey<OTS, LMS, 42> =
            HssPublicKey::from_binary_representation(binary_representation.as_slice())
                .expect("Deserialization should work.");

        assert!(public_key == deserialized);
    }
}
