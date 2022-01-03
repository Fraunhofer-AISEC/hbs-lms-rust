use core::marker::PhantomData;

use crate::hasher::{sha256::Sha256, HashChain};

/// Specifies the used Tree height.
#[derive(Clone, Copy)]
pub enum LmsAlgorithm {
    LmsReserved = 0,
    #[cfg(test)]
    LmsH2 = 1,
    LmsH5 = 5,
    LmsH10 = 6,
    LmsH15 = 7,
    LmsH20 = 8,
    LmsH25 = 9,
}

impl Default for LmsAlgorithm {
    fn default() -> Self {
        LmsAlgorithm::LmsReserved
    }
}

impl From<u32> for LmsAlgorithm {
    fn from(_type: u32) -> Self {
        match _type {
            #[cfg(test)]
            1 => LmsAlgorithm::LmsH2,
            5 => LmsAlgorithm::LmsH5,
            6 => LmsAlgorithm::LmsH10,
            7 => LmsAlgorithm::LmsH15,
            8 => LmsAlgorithm::LmsH20,
            9 => LmsAlgorithm::LmsH25,
            _ => LmsAlgorithm::LmsReserved,
        }
    }
}

impl LmsAlgorithm {
    pub fn construct_default_parameter() -> LmsParameter {
        LmsAlgorithm::LmsH5.construct_parameter().unwrap()
    }

    pub fn construct_parameter<H: HashChain>(&self) -> Option<LmsParameter<H>> {
        match *self {
            LmsAlgorithm::LmsReserved => None,
            #[cfg(test)]
            LmsAlgorithm::LmsH2 => Some(LmsParameter::new(1, 2)),
            LmsAlgorithm::LmsH5 => Some(LmsParameter::new(5, 5)),
            LmsAlgorithm::LmsH10 => Some(LmsParameter::new(6, 10)),
            LmsAlgorithm::LmsH15 => Some(LmsParameter::new(7, 15)),
            LmsAlgorithm::LmsH20 => Some(LmsParameter::new(8, 20)),
            LmsAlgorithm::LmsH25 => Some(LmsParameter::new(9, 25)),
        }
    }

    pub fn get_from_type<H: HashChain>(_type: u32) -> Option<LmsParameter<H>> {
        match _type {
            #[cfg(test)]
            1 => LmsAlgorithm::LmsH2.construct_parameter(),
            5 => LmsAlgorithm::LmsH5.construct_parameter(),
            6 => LmsAlgorithm::LmsH10.construct_parameter(),
            7 => LmsAlgorithm::LmsH15.construct_parameter(),
            8 => LmsAlgorithm::LmsH20.construct_parameter(),
            9 => LmsAlgorithm::LmsH25.construct_parameter(),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LmsParameter<H: HashChain = Sha256> {
    type_id: u32,
    tree_height: u8,
    phantom_data: PhantomData<H>,
}

// Manually implement Copy because HashChain trait does not.
// However, it does not make a difference, because we don't hold a instance for HashChain.
impl<H: HashChain> Copy for LmsParameter<H> {}

impl<H: HashChain> LmsParameter<H> {
    const HASH_FUNCTION_OUTPUT_SIZE: usize = H::OUTPUT_SIZE as usize;

    pub fn new(type_id: u32, tree_height: u8) -> Self {
        Self {
            type_id,
            tree_height,
            phantom_data: PhantomData,
        }
    }

    pub fn get_type_id(&self) -> u32 {
        self.type_id
    }

    pub fn get_hash_function_output_size(&self) -> usize {
        Self::HASH_FUNCTION_OUTPUT_SIZE
    }

    pub fn get_tree_height(&self) -> u8 {
        self.tree_height
    }

    pub fn number_of_lm_ots_keys(&self) -> usize {
        2usize.pow(self.tree_height as u32)
    }

    pub fn get_hasher(&self) -> H {
        H::default()
    }
}

impl<H: HashChain> Default for LmsParameter<H> {
    fn default() -> Self {
        LmsAlgorithm::LmsH5.construct_parameter().unwrap()
    }
}
