use sha2::{Digest, Sha256};

use crate::{
    constants::MAX_N,
    lm_ots::definitions::{IType, QType},
    util::{
        dynamic_array::DynamicArray,
        ustr::{u16str, u8str},
    },
};

use super::Hasher;

pub struct Sha256Hasher {
    hasher: Sha256,
}

impl Sha256Hasher {
    pub fn new() -> Self {
        Sha256Hasher {
            hasher: Sha256::default(),
        }
    }
}

impl Hasher for Sha256Hasher {
    const OUTPUT_SIZE: usize = 32;

    fn get_hasher() -> Self {
        Self::new()
    }

    fn update(&mut self, data: &[u8]) {
        self.hasher.update(data);
    }

    fn finalize(self) -> DynamicArray<u8, MAX_N> {
        DynamicArray::from_slice(self.hasher.finalize().iter().as_slice())
    }

    fn finalize_reset(&mut self) -> DynamicArray<u8, MAX_N> {
        DynamicArray::from_slice(self.hasher.finalize_reset().iter().as_slice())
    }

    #[allow(non_snake_case)]
    fn do_hash_chain<'a>(
        &mut self,
        I: &IType,
        q: &QType,
        i: u16,
        from: usize,
        to: usize,
        start: &'a mut [u8],
    ) {
        for j in from..to {
            self.update(I);
            self.update(q);
            self.update(&u16str(i));
            self.update(&u8str(j as u8));
            self.update(start);
            start.copy_from_slice(self.finalize_reset().get_slice());
        }
    }
}
