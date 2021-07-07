use core::marker::PhantomData;

use crate::{constants::MAX_N, hasher::Hasher, util::{coef::coef, dynamic_array::DynamicArray}};

pub enum LmotsAlgorithm {
    LmotsReserved = 0,
    LmotsW1 = 1,
    LmotsW2 = 2,
    LmotsW4 = 3,
    LmotsW8 = 4
}

impl LmotsAlgorithm {
    pub fn construct_parameter<H: Hasher>(&self) -> Option<LmotsParameter<H>> {
        match *self {
            LmotsAlgorithm::LmotsReserved => None,
            LmotsAlgorithm::LmotsW1 => Some(LmotsParameter::new(1, 1, 265, 7)),
            LmotsAlgorithm::LmotsW2 => Some(LmotsParameter::new(2, 2, 133, 6)),
            LmotsAlgorithm::LmotsW4 => Some(LmotsParameter::new(3, 4, 67, 4)),
            LmotsAlgorithm::LmotsW8 => Some(LmotsParameter::new(4, 8, 34, 0)),
        }        
    }

    pub fn get_from_type<H: Hasher>(_type: u32) -> Option<LmotsParameter<H>> {
        match _type {
            1 =>
        }
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub struct LmotsParameter<H: Hasher> {
    id: u32,
    winternitz: u8,
    p: u16,
    ls: u8,
    phantom_data: PhantomData<H>
}

impl<H: Hasher> LmotsParameter<H> {
    const N: usize = H::OUTPUT_SIZE;

    pub fn new(id: u32, winternitz: u8, p: u16, ls: u8) -> Self {
        Self {
            id, winternitz, p, ls, phantom_data: PhantomData
        }
    }

    pub fn get_type(&self) -> u32 {
        self.id
    }

    pub fn get_winternitz(&self) -> u8 {
        self.winternitz
    }

    pub fn get_p(&self) -> u16 {
        self.p
    }

    pub fn get_ls(&self) -> u8 {
        self.ls
    }

    fn checksum(&self, byte_string: &[u8]) -> u16 {
        let mut sum = 0_u16;
        let max: u64 = ((Self::N * 8) as f64 / self.get_winternitz() as f64) as u64;
        let max_word_size: u64 = (1 << self.get_winternitz()) - 1;

        for i in 0..max {
            sum += (max_word_size - coef(byte_string, i, self.get_winternitz() as u64)) as u16;
        }

        sum << self.get_ls()
    }

    fn get_appended_with_checksum(&self, byte_string: &[u8]) -> DynamicArray<u8, { MAX_N + 2 }> {
        let mut result = DynamicArray::new();

        let checksum = self.checksum(byte_string);

        result.append(byte_string);

        result.append(&[(checksum >> 8 & 0xff) as u8]);
        result.append(&[(checksum & 0xff) as u8]);

        result
    }
}