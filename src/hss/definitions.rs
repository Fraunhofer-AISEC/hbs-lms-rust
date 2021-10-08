use arrayvec::ArrayVec;

use crate::{
    constants::{MAX_HSS_LEVELS, MAX_LMS_PUBLIC_KEY_LENGTH},
    hasher::Hasher,
    hss::aux::{
        hss_expand_aux_data, hss_finalize_aux_data, hss_optimal_aux_level, hss_store_aux_marker,
    },
    lms::{
        definitions::InMemoryLmsPublicKey, generate_key_pair_with_seed_and_aux,
        parameters::LmsParameter,
    },
    util::{
        helper::read_and_advance,
        ustr::{str32u, u32str},
    },
};
use crate::{
    hss::aux::hss_get_aux_data_len,
    lms::{
        self,
        definitions::{LmsPrivateKey, LmsPublicKey},
        signing::LmsSignature,
    },
};

use super::rfc_private_key::RfcPrivateKey;
use super::{
    aux::{hss_is_aux_data_used, MutableExpandedAuxData},
    rfc_private_key::generate_child_seed_and_lms_tree_identifier,
};

#[derive(Default, PartialEq)]
pub struct HssPrivateKey<H: Hasher> {
    pub private_key: ArrayVec<LmsPrivateKey<H>, MAX_HSS_LEVELS>,
    pub public_key: ArrayVec<LmsPublicKey<H>, MAX_HSS_LEVELS>,
    pub signatures: ArrayVec<LmsSignature<H>, { MAX_HSS_LEVELS - 1 }>, // Only L - 1 signatures needed
}

impl<H: Hasher> HssPrivateKey<H> {
    pub fn get_length(&self) -> usize {
        self.private_key.len()
    }

    pub fn from(
        private_key: &RfcPrivateKey<H>,
        aux_data: Option<&mut &mut [u8]>,
    ) -> Result<Self, ()> {
        let parameters = private_key.compressed_parameter.to::<H>();
        let levels = parameters.len();

        let top_lms_parameter = parameters[0].get_lms_parameter();

        let is_aux_data_used = if let Some(ref aux_data) = aux_data {
            hss_is_aux_data_used(aux_data)
        } else {
            false
        };

        let mut expanded_aux_data = HssPrivateKey::get_expanded_aux_data(
            aux_data,
            private_key,
            top_lms_parameter,
            is_aux_data_used,
        );

        let mut hss_private_key: HssPrivateKey<H> = Default::default();

        let mut current_seed = private_key.generate_root_seed_and_lms_tree_identifier();

        let lms_keypair = generate_key_pair_with_seed_and_aux(
            &current_seed,
            &parameters[0],
            &mut expanded_aux_data,
        );

        hss_private_key.private_key.push(lms_keypair.private_key);
        hss_private_key.public_key.push(lms_keypair.public_key);

        for i in 1..levels {
            let parameter = &parameters[i];

            current_seed = generate_child_seed_and_lms_tree_identifier(&current_seed, i as u32);

            let lms_keypair =
                generate_key_pair_with_seed_and_aux(&current_seed, parameter, &mut None);

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

        if let Some(expanded_aux_data) = expanded_aux_data.as_mut() {
            if !is_aux_data_used {
                hss_finalize_aux_data::<H>(expanded_aux_data, &private_key.seed);
            }
        }

        Ok(hss_private_key)
    }

    fn get_expanded_aux_data<'a>(
        aux_data: Option<&'a mut &mut [u8]>,
        private_key: &'a RfcPrivateKey<H>,
        top_lms_parameter: &LmsParameter<H>,
        is_aux_data_used: bool,
    ) -> Option<MutableExpandedAuxData<'a>> {
        if let Some(aux_data) = aux_data {
            if is_aux_data_used {
                hss_expand_aux_data::<H>(Some(aux_data), Some(&private_key.seed))
            } else {
                let aux_len = hss_get_aux_data_len(aux_data.len(), *top_lms_parameter);

                // Shrink input slice
                let moved = core::mem::replace(aux_data, &mut []);
                *aux_data = &mut moved[..aux_len];

                let aux_level = hss_optimal_aux_level(aux_len, *top_lms_parameter, None);
                hss_store_aux_marker(aux_data, aux_level);

                hss_expand_aux_data::<H>(Some(aux_data), None)
            }
        } else {
            None
        }
    }

    pub fn get_public_key(&self) -> HssPublicKey<H> {
        HssPublicKey {
            public_key: self.public_key[0].clone(),
            level: self.get_length(),
        }
    }
}

#[derive(PartialEq)]
pub struct HssPublicKey<H: Hasher> {
    pub public_key: LmsPublicKey<H>,
    pub level: usize,
}

/// To reduce memory footprint on verification we handle the public key in-memory using ```InMemoryHssPublicKey```.
/// In order to reduce complexity we use ```HssPublicKey``` for key generation and signature generation.
pub struct InMemoryHssPublicKey<'a, H: Hasher> {
    pub public_key: InMemoryLmsPublicKey<'a, H>,
    pub level: usize,
}

impl<'a, H: Hasher> PartialEq<HssPublicKey<H>> for InMemoryHssPublicKey<'a, H> {
    fn eq(&self, other: &HssPublicKey<H>) -> bool {
        self.public_key == other.public_key && self.level == other.level
    }
}

impl<H: Hasher> HssPublicKey<H> {
    pub fn to_binary_representation(&self) -> ArrayVec<u8, { 4 + MAX_LMS_PUBLIC_KEY_LENGTH }> {
        let mut result = ArrayVec::new();

        result
            .try_extend_from_slice(&u32str(self.level as u32))
            .unwrap();
        result
            .try_extend_from_slice(self.public_key.to_binary_representation().as_slice())
            .unwrap();

        result
    }
}

impl<'a, H: Hasher> InMemoryHssPublicKey<'a, H> {
    pub fn new(data: &'a [u8]) -> Option<Self> {
        let mut index = 0;

        let level = str32u(read_and_advance(data, 4, &mut index));

        let public_key = match InMemoryLmsPublicKey::new(&data[index..]) {
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
    use crate::hss::definitions::InMemoryHssPublicKey;
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

        let deserialized = InMemoryHssPublicKey::new(binary_representation.as_slice())
            .expect("Deserialization should work.");

        assert!(deserialized == public_key);
    }
}
