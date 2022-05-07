use tinyvec::TinyVec;

use crate::{
    constants::{
        LmsTreeIdentifier, Seed, ILEN, MAX_HASH_SIZE, PRNG_FF, PRNG_I, PRNG_J, PRNG_MAX_LEN,
        PRNG_Q, PRNG_SEED, SEED_LEN,
    },
    hasher::HashChain,
};

pub struct SeedDerive<'a> {
    master_seed: &'a Seed,
    lms_tree_identifier: &'a LmsTreeIdentifier,
    lms_leaf_identifier: u32,
    child_seed: u16,
}

impl<'a> SeedDerive<'a> {
    pub fn new(seed: &'a Seed, i: &'a LmsTreeIdentifier) -> Self {
        SeedDerive {
            master_seed: seed,
            lms_tree_identifier: i,
            lms_leaf_identifier: 0,
            child_seed: 0,
        }
    }

    pub fn set_lms_leaf_identifier(&mut self, identifier: u32) {
        self.lms_leaf_identifier = identifier;
    }

    pub fn set_child_seed(&mut self, seed: u16) {
        self.child_seed = seed;
    }

    pub fn seed_derive<H: HashChain>(&mut self, increment_j: bool) -> TinyVec<[u8; MAX_HASH_SIZE]> {
        let mut buffer = [0u8; PRNG_MAX_LEN];

        buffer[PRNG_I..PRNG_I + ILEN].copy_from_slice(self.lms_tree_identifier);
        buffer[PRNG_Q..PRNG_Q + 4].copy_from_slice(&self.lms_leaf_identifier.to_be_bytes());
        buffer[PRNG_J..PRNG_J + 2].copy_from_slice(&self.child_seed.to_be_bytes());
        buffer[PRNG_FF] = 0xff;
        buffer[PRNG_SEED..PRNG_SEED + SEED_LEN].copy_from_slice(self.master_seed);

        if increment_j {
            self.child_seed += 1;
        }

        H::default().chain(&buffer).finalize()
    }
}
