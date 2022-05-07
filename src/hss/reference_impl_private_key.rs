use crate::{
    constants::{
        LmsTreeIdentifier, Seed, D_TOPSEED, ILEN, LMS_LEAF_IDENTIFIERS_SIZE,
        MAX_ALLOWED_HSS_LEVELS, MAX_HASH_SIZE, REFERENCE_IMPL_PRIVATE_KEY_SIZE, SEED_CHILD_SEED,
        SEED_LEN, SEED_SIGNATURE_RANDOMIZER_SEED, TOPSEED_D, TOPSEED_LEN, TOPSEED_SEED,
        TOPSEED_WHICH,
    },
    hasher::HashChain,
    hss::{definitions::HssPrivateKey, seed_derive::SeedDerive},
    util::helper::read_and_advance,
    HssParameter, LmotsAlgorithm, LmsAlgorithm,
};

use core::{convert::TryInto, marker::PhantomData, mem::size_of};
use tinyvec::TinyVec;

/**
To be compatible with the reference implementation
 */

#[derive(Default)]
pub struct SeedAndLmsTreeIdentifier {
    pub seed: Seed,
    pub lms_tree_identifier: LmsTreeIdentifier,
}

impl SeedAndLmsTreeIdentifier {
    pub fn new(seed: &[u8; SEED_LEN], lms_tree_identifier: &[u8; ILEN]) -> Self {
        let mut result = SeedAndLmsTreeIdentifier::default();

        result.seed.copy_from_slice(seed);
        result
            .lms_tree_identifier
            .copy_from_slice(lms_tree_identifier);

        result
    }
}

#[derive(Default, PartialEq)]
pub struct ReferenceImplPrivateKey<H: HashChain> {
    pub compressed_used_leafs_indexes: CompressedUsedLeafsIndexes,
    pub compressed_parameter: CompressedParameterSet,
    pub seed: Seed,
    phantom: PhantomData<H>,
}

impl<H: HashChain> ReferenceImplPrivateKey<H> {
    fn wipe(&mut self) {
        self.seed = [0u8; SEED_LEN] as Seed;
        self.compressed_parameter = CompressedParameterSet::default();
        self.compressed_used_leafs_indexes = CompressedUsedLeafsIndexes::new(0);
    }

    pub fn generate(parameters: &[HssParameter<H>], seed: &[u8; SEED_LEN]) -> Result<Self, ()> {
        let mut private_key: ReferenceImplPrivateKey<H> = ReferenceImplPrivateKey {
            compressed_used_leafs_indexes: CompressedUsedLeafsIndexes::new(0),
            compressed_parameter: CompressedParameterSet::from(parameters)?,
            ..Default::default()
        };

        private_key.seed.copy_from_slice(seed);

        Ok(private_key)
    }

    pub fn to_binary_representation(&self) -> TinyVec<[u8; REFERENCE_IMPL_PRIVATE_KEY_SIZE]> {
        let mut result = TinyVec::new();

        result.extend_from_slice(&self.compressed_used_leafs_indexes.count.to_be_bytes());
        result.extend_from_slice(&self.compressed_parameter.0);
        result.extend_from_slice(&self.seed);

        result
    }

    pub fn from_binary_representation(data: &[u8]) -> Result<Self, ()> {
        if data.len() != REFERENCE_IMPL_PRIVATE_KEY_SIZE {
            return Err(());
        }

        let mut result = Self::default();
        let mut index = 0;

        let compressed_used_leafs_indexes =
            read_and_advance(data, LMS_LEAF_IDENTIFIERS_SIZE, &mut index);
        result.compressed_used_leafs_indexes =
            CompressedUsedLeafsIndexes::from_slice(compressed_used_leafs_indexes);

        let compressed_parameter = read_and_advance(data, MAX_ALLOWED_HSS_LEVELS, &mut index);
        result.compressed_parameter = CompressedParameterSet::from_slice(compressed_parameter)?;

        result
            .seed
            .copy_from_slice(read_and_advance(data, size_of::<Seed>(), &mut index));

        Ok(result)
    }

    pub fn generate_root_seed_and_lms_tree_identifier(&self) -> SeedAndLmsTreeIdentifier {
        let mut hash_preimage = [0u8; TOPSEED_LEN];
        let mut hash_postimage = [0u8; MAX_HASH_SIZE];

        hash_preimage[TOPSEED_D] = (D_TOPSEED >> 8) as u8;
        hash_preimage[TOPSEED_D + 1] = (D_TOPSEED & 0xff) as u8;

        let start = TOPSEED_SEED;
        let end = start + size_of::<Seed>();
        hash_preimage[start..end].copy_from_slice(&self.seed);

        let mut hasher = H::default();

        hasher.update(&hash_preimage);
        hash_postimage.copy_from_slice(hasher.finalize_reset().as_slice());

        hash_preimage[start..end].copy_from_slice(&hash_postimage);

        hash_preimage[TOPSEED_WHICH] = 0x01;
        hasher.update(&hash_preimage);

        let seed: [u8; 32] = hasher
            .finalize_reset()
            .into_iter()
            .as_slice()
            .try_into()
            .unwrap();

        hash_preimage[TOPSEED_WHICH] = 0x02;
        hasher.update(&hash_preimage);

        let mut lms_tree_identifier = LmsTreeIdentifier::default();
        lms_tree_identifier.copy_from_slice(&hasher.finalize_reset()[..ILEN]);

        SeedAndLmsTreeIdentifier::new(&seed, &lms_tree_identifier)
    }

    pub fn increment(&mut self, hss_private_key: &HssPrivateKey<H>) {
        let tree_heights = hss_private_key
            .private_key
            .iter()
            .map(|pk| pk.lms_parameter.get_tree_height())
            .collect();
        self.compressed_used_leafs_indexes
            .increment(&tree_heights)
            .unwrap_or_else(|_| self.wipe());
    }
}

pub fn generate_child_seed_and_lms_tree_identifier<H: HashChain>(
    parent_seed: &SeedAndLmsTreeIdentifier,
    parent_lms_leaf_identifier: &u32,
) -> SeedAndLmsTreeIdentifier {
    let mut derive = SeedDerive::new(&parent_seed.seed, &parent_seed.lms_tree_identifier);

    derive.set_lms_leaf_identifier(*parent_lms_leaf_identifier);
    derive.set_child_seed(SEED_CHILD_SEED);

    let seed = derive
        .seed_derive::<H>(true)
        .into_iter()
        .as_slice()
        .try_into()
        .unwrap();
    let mut lms_tree_identifier = LmsTreeIdentifier::default();
    lms_tree_identifier.copy_from_slice(&derive.seed_derive::<H>(false)[..ILEN]);

    SeedAndLmsTreeIdentifier::new(&seed, &lms_tree_identifier)
}

pub fn generate_signature_randomizer<H: HashChain>(
    child_seed: &SeedAndLmsTreeIdentifier,
    parent_lms_leaf_identifier: &u32,
) -> TinyVec<[u8; MAX_HASH_SIZE]> {
    let mut derive = SeedDerive::new(&child_seed.seed, &child_seed.lms_tree_identifier);

    derive.set_lms_leaf_identifier(*parent_lms_leaf_identifier);
    derive.set_child_seed(SEED_SIGNATURE_RANDOMIZER_SEED);

    derive.seed_derive::<H>(false)
}

const PARAM_SET_END: u8 = 0xff; // Marker for end of parameter set

#[derive(PartialEq)]
pub struct CompressedParameterSet([u8; MAX_ALLOWED_HSS_LEVELS]);

impl Default for CompressedParameterSet {
    fn default() -> Self {
        Self([PARAM_SET_END; MAX_ALLOWED_HSS_LEVELS])
    }
}

impl CompressedParameterSet {
    pub fn from_slice(data: &[u8]) -> Result<Self, ()> {
        if data.len() != MAX_ALLOWED_HSS_LEVELS {
            return Err(());
        }

        let mut result = CompressedParameterSet::default();
        result.0.copy_from_slice(data);

        Ok(result)
    }

    pub fn from<H: HashChain>(parameters: &[HssParameter<H>]) -> Result<Self, ()> {
        let mut result = CompressedParameterSet::default();

        for (i, parameter) in parameters.iter().enumerate() {
            let lmots = parameter.get_lmots_parameter();
            let lms = parameter.get_lms_parameter();

            let lmots_type = lmots.get_type_id() as u8;
            let lms_type = lms.get_type_id() as u8;

            result.0[i] = (lms_type << 4) + lmots_type;
        }

        Ok(result)
    }

    pub fn to<H: HashChain>(
        &self,
    ) -> Result<TinyVec<[HssParameter<H>; MAX_ALLOWED_HSS_LEVELS]>, ()> {
        let mut result = TinyVec::new();

        for level in 0..MAX_ALLOWED_HSS_LEVELS {
            let parameter = self.0[level];

            if parameter == PARAM_SET_END {
                break;
            }

            let lms_type = parameter >> 4;
            let lmots_type = parameter & 0x0f;

            let lms = LmsAlgorithm::from(lms_type as u32);
            let lmots = LmotsAlgorithm::from(lmots_type as u32);

            result.extend_from_slice(&[HssParameter::new(lmots, lms)]);
        }

        if result.is_empty() {
            return Err(());
        }

        Ok(result)
    }
}

#[derive(Default, PartialEq)]
pub struct CompressedUsedLeafsIndexes {
    count: u64,
}

impl CompressedUsedLeafsIndexes {
    pub fn new(count: u64) -> Self {
        CompressedUsedLeafsIndexes { count }
    }

    pub fn from_slice(data: &[u8]) -> Self {
        CompressedUsedLeafsIndexes {
            count: u64::from_be_bytes(data.try_into().unwrap()),
        }
    }

    pub fn to<H: HashChain>(
        &self,
        parameters: &TinyVec<[HssParameter<H>; MAX_ALLOWED_HSS_LEVELS]>,
    ) -> [u32; MAX_ALLOWED_HSS_LEVELS] {
        let mut lms_leaf_identifier_set = [0u32; MAX_ALLOWED_HSS_LEVELS];
        let mut compressed_used_leafs_indexes = self.count;

        for (i, parameter) in parameters.iter().enumerate().rev() {
            let tree_height: u32 = parameter.get_lms_parameter().get_tree_height().into();
            lms_leaf_identifier_set[i] =
                (compressed_used_leafs_indexes & (2u32.pow(tree_height) - 1) as u64) as u32;
            compressed_used_leafs_indexes >>= tree_height;
        }
        lms_leaf_identifier_set
    }

    pub fn increment(
        &mut self,
        tree_heights: &TinyVec<[u8; MAX_ALLOWED_HSS_LEVELS]>,
    ) -> Result<(), ()> {
        let total_tree_height: u32 = tree_heights.iter().sum::<u8>().into();

        if self.count >= (2u64.pow(total_tree_height) - 1) {
            return Err(());
        }

        self.count += 1;
        Ok(())
    }
}

#[cfg(test)]
mod tests {

    use super::{CompressedParameterSet, ReferenceImplPrivateKey};
    use crate::{
        constants::MAX_ALLOWED_HSS_LEVELS, hss::definitions::HssPrivateKey, HssParameter,
        LmotsAlgorithm, LmsAlgorithm, Seed, Sha256,
    };

    use rand::{rngs::OsRng, RngCore};
    use tinyvec::TinyVec;

    type Hasher = Sha256;

    #[test]
    fn exhaust_state() {
        let lmots = LmotsAlgorithm::LmotsW4;
        let lms = LmsAlgorithm::LmsH5;
        let parameters = [HssParameter::<Hasher>::new(lmots, lms)];

        let mut seed = Seed::default();
        OsRng.fill_bytes(&mut seed);
        let mut rfc_private_key = ReferenceImplPrivateKey::generate(&parameters, &seed).unwrap();

        let hss_private_key = HssPrivateKey::from(&rfc_private_key, &mut None).unwrap();

        let seed = rfc_private_key.seed;

        let tree_heights = parameters
            .iter()
            .map(|parameter| parameter.get_lms_parameter().get_tree_height())
            .collect::<TinyVec<[u8; MAX_ALLOWED_HSS_LEVELS]>>();

        for _ in 0..2u64.pow(tree_heights.as_slice().iter().sum::<u8>().into()) {
            assert_eq!(rfc_private_key.seed, seed);
            rfc_private_key.increment(&hss_private_key);
        }

        assert_ne!(rfc_private_key.seed, seed);
    }

    #[test]
    #[should_panic(expected = "Parsing should panic!")]
    fn parse_exhausted_state() {
        let lmots = LmotsAlgorithm::LmotsW4;
        let lms = LmsAlgorithm::LmsH5;
        let parameters = [HssParameter::<Hasher>::new(lmots, lms)];

        let mut seed = Seed::default();
        OsRng.fill_bytes(&mut seed);
        let mut rfc_private_key = ReferenceImplPrivateKey::generate(&parameters, &seed).unwrap();

        let hss_private_key = HssPrivateKey::from(&rfc_private_key, &mut None).unwrap();
        let keypair_lifetime = hss_private_key.get_lifetime();

        for _ in 0..keypair_lifetime {
            let _ = rfc_private_key
                .compressed_parameter
                .to::<Hasher>()
                .expect("Parsing should complete without error");
            rfc_private_key.increment(&hss_private_key);
        }
        let _ = rfc_private_key
            .compressed_parameter
            .to::<Hasher>()
            .expect("Parsing should panic!");
    }

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
        let arr = compressed.to::<Hasher>().unwrap();

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

        let mut seed = Seed::default();
        OsRng.fill_bytes(&mut seed);
        let key = ReferenceImplPrivateKey::generate(&parameters, &seed).unwrap();

        let binary_representation = key.to_binary_representation();
        let deserialized = ReferenceImplPrivateKey::<Hasher>::from_binary_representation(
            binary_representation.as_slice(),
        )
        .unwrap();

        assert!(key == deserialized);
    }
}
