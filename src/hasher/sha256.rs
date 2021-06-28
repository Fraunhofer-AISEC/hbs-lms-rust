use sha2::{Digest, Sha256};

use crate::{constants::MAX_N, util::dynamic_array::DynamicArray};

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
}
