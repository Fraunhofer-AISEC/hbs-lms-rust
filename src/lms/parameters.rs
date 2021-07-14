use core::marker::PhantomData;

use crate::hasher::{sha256::Sha256Hasher, Hasher};

#[derive(Clone, Copy)]
pub enum LmsAlgorithm {
    LmsReserved = 0,
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

    pub fn construct_parameter<H: Hasher>(&self) -> Option<LmsParameter<H>> {
        match *self {
            LmsAlgorithm::LmsReserved => None,
            LmsAlgorithm::LmsH5 => Some(LmsParameter::new(5, 5)),
            LmsAlgorithm::LmsH10 => Some(LmsParameter::new(6, 10)),
            LmsAlgorithm::LmsH15 => Some(LmsParameter::new(7, 15)),
            LmsAlgorithm::LmsH20 => Some(LmsParameter::new(8, 20)),
            LmsAlgorithm::LmsH25 => Some(LmsParameter::new(9, 25)),
        }
    }

    pub fn get_from_type<H: Hasher>(_type: u32) -> Option<LmsParameter<H>> {
        match _type {
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
pub struct LmsParameter<H: Hasher = Sha256Hasher> {
    id: u32,
    height: u8,
    phantom_data: PhantomData<H>,
}

// Manually implement Copy because Hasher trait does not.
// However, it does not make a difference, because we don't hold a instance for Hasher.
impl<H: Hasher> Copy for LmsParameter<H> {}

impl<H: Hasher> LmsParameter<H> {
    const M: usize = H::OUTPUT_SIZE;

    pub fn new(id: u32, height: u8) -> Self {
        Self {
            id,
            height,
            phantom_data: PhantomData,
        }
    }

    pub fn get_type(&self) -> u32 {
        self.id
    }

    pub fn get_m(&self) -> usize {
        Self::M
    }

    pub fn get_height(&self) -> u8 {
        self.height
    }

    pub fn number_of_lm_ots_keys(&self) -> usize {
        2usize.pow(self.height as u32)
    }

    pub fn get_hasher(&self) -> H {
        <H>::get_hasher()
    }
}

impl<H: Hasher> Default for LmsParameter<H> {
    fn default() -> Self {
        LmsAlgorithm::LmsH5.construct_parameter().unwrap()
    }
}
