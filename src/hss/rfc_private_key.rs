use core::{marker::PhantomData, mem::size_of};

use crate::{
    constants::{
        LmsTreeIdentifier, Seed, D_TOPSEED, MAX_HASH, MAX_HSS_LEVELS, RFC_PRIVATE_KEY_SIZE, SEED_CHILD_SEED,
        TOPSEED_D, TOPSEED_LEN, TOPSEED_SEED, TOPSEED_WHICH,
    },
    extract_or_return,
    hasher::Hasher,
    hss::seed_derive::SeedDerive,
    util::{
        dynamic_array::DynamicArray,
        helper::read_and_advance,
        random::get_random,
        ustr::{str64u, u64str},
    },
    HssParameter, LmotsAlgorithm, LmsAlgorithm,
};

/**
To be compatible with the reference implementation
 */

#[derive(Default, PartialEq)]
pub struct RfcPrivateKey<H: Hasher> {
    pub q: u64,
    pub compressed_parameter: CompressedParameterSet,
    pub seed: Seed,
    phantom: PhantomData<H>,
}

pub struct SeedAndI {
    pub seed: Seed,
    pub i: LmsTreeIdentifier,
}

impl SeedAndI {
    pub fn new(seed: &[u8], i: &[u8]) -> Self {
        let mut local_seed: Seed = Default::default();
        let mut local_i: LmsTreeIdentifier = Default::default();

        local_seed.copy_from_slice(seed);
        local_i.copy_from_slice(&i[..16]);

        Self {
            seed: local_seed,
            i: local_i,
        }
    }
}

impl<H: Hasher> RfcPrivateKey<H> {
    pub fn generate_with_seed(parameters: &[HssParameter<H>], seed: &[u8]) -> Option<Self> {
        let mut private_key: RfcPrivateKey<H> = RfcPrivateKey {
            q: 0,
            compressed_parameter: extract_or_return!(CompressedParameterSet::from(parameters)),
            ..Default::default()
        };

        if seed.len() < 32 {
            return None;
        }

        private_key.seed.copy_from_slice(&seed[..32]);

        Some(private_key)
    }

    pub fn generate(parameters: &[HssParameter<H>]) -> Option<Self> {
        let mut seed: Seed = Default::default();
        get_random(&mut seed);

        RfcPrivateKey::generate_with_seed(parameters, &seed)
    }

    pub fn to_binary_representation(&self) -> DynamicArray<u8, RFC_PRIVATE_KEY_SIZE> {
        let mut result = DynamicArray::new();

        result.append(&u64str(self.q));
        result.append(&self.compressed_parameter.0);
        result.append(&self.seed);

        result
    }

    pub fn from_binary_representation(data: &[u8]) -> Option<Self> {
        if data.len() != RFC_PRIVATE_KEY_SIZE {
            return None;
        }

        let mut result = Self::default();
        let mut index = 0;

        let q = read_and_advance(data, 8, &mut index);
        result.q = str64u(q);

        let compressed_parameter = read_and_advance(data, MAX_HSS_LEVELS, &mut index);
        result.compressed_parameter =
            extract_or_return!(CompressedParameterSet::from_slice(compressed_parameter));

        result
            .seed
            .copy_from_slice(read_and_advance(data, size_of::<Seed>(), &mut index));

        Some(result)
    }

    pub fn generate_root_seed_I_value(&self) -> SeedAndI {
        let mut hash_preimage = [0u8; TOPSEED_LEN];
        let mut hash_postimage = [0u8; MAX_HASH];

        hash_preimage[TOPSEED_D] = (D_TOPSEED >> 8) as u8;
        hash_preimage[TOPSEED_D + 1] = (D_TOPSEED & 0xff) as u8;

        let start = TOPSEED_SEED;
        let end = start + size_of::<Seed>();
        hash_preimage[start..end].copy_from_slice(&self.seed);

        let mut hasher = H::get_hasher();

        hasher.update(&hash_preimage);
        hash_postimage.copy_from_slice(hasher.finalize_reset().as_slice());

        hash_preimage[start..end].copy_from_slice(&hash_postimage);

        hash_preimage[TOPSEED_WHICH] = 0x01;
        hasher.update(&hash_preimage);

        let seed = hasher.finalize_reset();

        hash_preimage[TOPSEED_WHICH] = 0x02;
        hasher.update(&hash_preimage);

        let i = hasher.finalize_reset();

        SeedAndI::new(seed.as_slice(), i.as_slice())
    }
}

pub fn generate_child_seed_I_value(parent_seed: &SeedAndI, index: u32) -> SeedAndI {
    let mut derive = SeedDerive::new(&parent_seed.seed, &parent_seed.i);

    derive.set_q(index);
    derive.set_j(SEED_CHILD_SEED);

    let seed = derive.seed_derive(true);
    let i = derive.seed_derive(false);

    SeedAndI::new(&seed, &i[..16])
}

const PARAM_SET_END: u8 = 0xff; // Marker for end of parameter set

#[derive(Default, PartialEq)]
pub struct CompressedParameterSet([u8; MAX_HSS_LEVELS]);

impl CompressedParameterSet {
    pub fn from_slice(data: &[u8]) -> Option<Self> {
        if data.len() != MAX_HSS_LEVELS {
            return None;
        }

        let mut result = CompressedParameterSet::default();
        result.0.copy_from_slice(data);

        Some(result)
    }

    pub fn from<H: Hasher>(parameters: &[HssParameter<H>]) -> Option<Self> {
        let mut result = [PARAM_SET_END; MAX_HSS_LEVELS];

        for (i, parameter) in parameters.iter().enumerate() {
            let lmots = parameter.get_lmots_parameter();
            let lms = parameter.get_lms_parameter();

            let lmots_type = lmots.get_type() as u8;
            let lms_type = lms.get_type() as u8;

            result[i] = (lms_type << 4) + lmots_type;
        }

        Some(Self(result))
    }

    pub fn to<H: Hasher>(&self) -> DynamicArray<HssParameter<H>, MAX_HSS_LEVELS> {
        let mut result = DynamicArray::new();

        for level in 0..MAX_HSS_LEVELS {
            let parameter = self.0[level];

            if parameter == PARAM_SET_END {
                break;
            }

            let lms_type = parameter >> 4;
            let lmots_type = parameter & 0x0f;

            let lms = LmsAlgorithm::from(lms_type as u32);
            let lmots = LmotsAlgorithm::from(lmots_type as u32);

            result.append(&[HssParameter::new(lmots, lms)]);
        }

        result
    }
}

#[cfg(test)]
mod tests {

    use super::{CompressedParameterSet, RfcPrivateKey};
    use crate::{HssParameter, LmotsAlgorithm, LmsAlgorithm, Sha256Hasher};

    type Hasher = Sha256Hasher;

    #[test]
    fn test_binary_representation_compressed_parameter() {
        let lmots_first = LmotsAlgorithm::LmotsW4;
        let lmots_second = LmotsAlgorithm::LmotsW8;

        let lms_first = LmsAlgorithm::LmsH5;
        let lms_second = LmsAlgorithm::LmsH10;

        let parameter = [
            HssParameter::new(lmots_first, lms_first),
            HssParameter::new(lmots_second, lms_second),
        ];

        let compressed = CompressedParameterSet::from(&parameter).unwrap();
        let arr = compressed.to::<Hasher>();

        for (i, p) in arr.iter().enumerate() {
            assert!(p == &parameter[i])
        }

        assert!(compressed == CompressedParameterSet::from_slice(&compressed.0).unwrap());
    }

    #[test]
    fn test_binary_representation_rfc_private_key() {
        let parameters = [
            HssParameter::construct_default_parameters(),
            HssParameter::construct_default_parameters(),
        ];

        let key = RfcPrivateKey::generate(&parameters).unwrap();

        let binary_representation = key.to_binary_representation();
        let deserialized =
            RfcPrivateKey::<Hasher>::from_binary_representation(binary_representation.as_slice())
                .unwrap();

        assert!(key == deserialized);
    }
}
