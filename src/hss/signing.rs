use crate::{
    constants::{
        lms_public_key_length, lms_signature_length, MAX_HSS_SIGNATURE_LENGTH,
        MAX_LMS_PUBLIC_KEY_LENGTH, MAX_LMS_SIGNATURE_LENGTH,
    },
    extract_or_return,
    lms::{self, definitions::LmsPublicKey, signing::LmsSignature},
    util::{
        dynamic_array::DynamicArray,
        helper::read_and_advance,
        ustr::{str32u, u32str},
    },
    LmotsParameter, LmsParameter,
};

use super::definitions::HssPrivateKey;

#[derive(PartialEq)]
pub struct HssSignature<OTS: LmotsParameter, LMS: LmsParameter, const L: usize> {
    pub level: usize,
    pub signed_public_keys: DynamicArray<HssSignedPublicKey<OTS, LMS>, L>,
    pub signature: LmsSignature<OTS, LMS>,
}

impl<OTS: LmotsParameter, LMS: LmsParameter, const L: usize> HssSignature<OTS, LMS, L> {
    pub fn sign(
        private_key: &mut HssPrivateKey<OTS, LMS, L>,
        message: &[u8],
    ) -> Result<HssSignature<OTS, LMS, L>, &'static str> {
        let prv = &mut private_key.private_key;
        let public = &mut private_key.public_key;
        let sig = &mut private_key.signatures;

        // Regenerate the keys if neccessary

        let mut d = L;

        while prv[d - 1].q == 2u32.pow(prv[d - 1].get_h() as u32) {
            d -= 1;
            if d == 0 {
                return Err("All keys are exhausted.");
            }
        }

        while d < L {
            let lms_key_pair = lms::generate_key_pair();
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
        sig[L - 1] = lms::signing::LmsSignature::sign(&mut prv[L - 1], message)?;

        let mut signed_public_keys = DynamicArray::new();

        // Create list of signed keys
        for i in 0..L - 1 {
            signed_public_keys.push(HssSignedPublicKey::new(
                sig[i].clone(),
                public[i + 1].clone(),
            ));
        }

        let signature = HssSignature {
            level: L - 1,
            signed_public_keys,
            signature: sig[L - 1].clone(),
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
            signed_public_keys.push(signed_public_key);
            index += HssSignedPublicKey::<OTS, LMS>::len();
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
pub struct HssSignedPublicKey<OTS: LmotsParameter, LMS: LmsParameter> {
    pub sig: LmsSignature<OTS, LMS>,
    pub public_key: LmsPublicKey<OTS, LMS>,
}

impl<OTS: LmotsParameter, LMS: LmsParameter> HssSignedPublicKey<OTS, LMS> {
    pub fn new(signature: LmsSignature<OTS, LMS>, public_key: LmsPublicKey<OTS, LMS>) -> Self {
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
            <OTS>::N,
            <OTS>::get_p() as usize,
            <LMS>::M,
            <LMS>::H as usize,
        );

        let public_key = match LmsPublicKey::from_binary_representation(&data[sig_size..]) {
            None => return None,
            Some(x) => x,
        };

        Some(Self { sig, public_key })
    }

    pub fn len() -> usize {
        let sig_size = lms_signature_length(
            <OTS>::N,
            <OTS>::get_p() as usize,
            <LMS>::M,
            <LMS>::H as usize,
        );
        let public_key_size = lms_public_key_length(<LMS>::M);

        sig_size + public_key_size
    }
}

#[cfg(test)]
mod tests {
    use crate::lm_ots::parameter::*;
    use crate::lms::parameter::*;

    use super::HssPrivateKey;
    use super::HssSignature;
    use super::HssSignedPublicKey;

    type OTS = LmotsSha256N32W2;
    type LMS = LmsSha256M32H5;
    const LEVEL: usize = 2;

    #[test]
    fn test_signed_public_key_binary_representation() {
        let mut keypair = crate::lms::generate_key_pair::<OTS, LMS>();

        let message = [3, 54, 32, 45, 67, 32, 12, 58, 29, 49];
        let signature = crate::lms::signing::LmsSignature::sign(&mut keypair.private_key, &message)
            .expect("Signing should work");

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
        let mut private_key =
            HssPrivateKey::<OTS, LMS, LEVEL>::generate().expect("Should geneerate HSS private key");
        let message = [2, 56, 123, 22, 42, 49, 22];

        let signature =
            HssSignature::sign(&mut private_key, &message).expect("Should generate HSS signature");

        let binary_representation = signature.to_binary_representation();
        let deserialized = HssSignature::<OTS, LMS, LEVEL>::from_binary_representation(
            binary_representation.as_slice(),
        )
        .expect("Deserialization should work.");

        assert!(signature == deserialized);
    }
}
