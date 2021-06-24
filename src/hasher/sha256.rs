use core::convert::TryInto;

use sha2::{Digest, Sha256};

use crate::constants::MAX_N;

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
    fn update(&mut self, data: &[u8]) {
        self.hasher.update(data);
    }

    fn finalize(self) -> [u8; MAX_N] {
        self.hasher
            .finalize()
            .iter()
            .as_slice()
            .try_into()
            .expect("Wrong length")
    }

    fn finalize_reset(&mut self) -> [u8; MAX_N] {
        self.hasher
            .finalize_reset()
            .iter()
            .as_slice()
            .try_into()
            .expect("Wrong length")
    }
}
