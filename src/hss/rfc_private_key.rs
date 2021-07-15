use core::mem::size_of;

use crate::{
    constants::{IType, Seed, MAX_HSS_LEVELS, RFC_PRIVATE_KEY_SIZE},
    extract_or_return,
    util::{
        dynamic_array::DynamicArray,
        helper::read_and_advance,
        random::get_random,
        ustr::{str64u, u64str},
    },
    LmotsAlgorithm, LmsAlgorithm, Sha256Hasher,
};

/**
To be compatible with the reference implementation
 */

#[derive(Default)]
pub struct RfcPrivateKey {
    pub q: u64,
    pub compressed_parameter: CompressedParameterSet,
    pub seed: Seed,
    pub i: IType,
}

impl RfcPrivateKey {
    pub fn generate(parameters: &[(LmotsAlgorithm, LmsAlgorithm)]) -> Option<Self> {
        let mut private_key: RfcPrivateKey = Default::default();

        private_key.q = 0;
        private_key.compressed_parameter =
            extract_or_return!(CompressedParameterSet::from(parameters));

        get_random(&mut private_key.seed);
        get_random(&mut private_key.i);

        Some(private_key)
    }

    pub fn to_binary_representation(&self) -> DynamicArray<u8, RFC_PRIVATE_KEY_SIZE> {
        let mut result = DynamicArray::new();

        result.append(&u64str(self.q));
        result.append(&self.compressed_parameter.0);
        result.append(&self.seed);
        result.append(&self.i);

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
        result
            .i
            .copy_from_slice(read_and_advance(data, size_of::<IType>(), &mut index));

        Some(result)
    }
}

const PARAM_SET_END: u8 = 0xff; // Marker for end of parameter set
type DefaultHasher = Sha256Hasher;

#[derive(Default)]
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

    pub fn from(parameters: &[(LmotsAlgorithm, LmsAlgorithm)]) -> Option<Self> {
        let mut result = [PARAM_SET_END; MAX_HSS_LEVELS];

        for (i, (lmots, lms)) in parameters.iter().enumerate() {
            let lmots = extract_or_return!(lmots.construct_parameter::<DefaultHasher>());
            let lms = extract_or_return!(lms.construct_parameter::<DefaultHasher>());

            let lmots_type = lmots.get_type() as u8;
            let lms_type = lms.get_type() as u8;

            result[i] = (lms_type << 4) + lmots_type;
        }

        Some(Self(result))
    }

    pub fn to(&self) -> DynamicArray<(LmotsAlgorithm, LmsAlgorithm), MAX_HSS_LEVELS> {
        let mut result = DynamicArray::new();

        let mut max_level = 0;
        for level in 0..MAX_HSS_LEVELS {
            let parameter = self.0[level];

            if parameter == PARAM_SET_END {
                break;
            }

            let lms_type = parameter >> 4;
            let lmots_type = parameter & 0x0f;

            let lms = LmsAlgorithm::from(lms_type as u32);
            let lmots = LmotsAlgorithm::from(lmots_type as u32);

            result.append(&[(lmots, lms)]);
            max_level = level;
        }

        result
    }
}
