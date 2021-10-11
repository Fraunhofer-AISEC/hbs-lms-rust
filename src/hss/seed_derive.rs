use crate::{
    constants::{
        prng_len, LmsTreeIdentifier, Seed, ILEN, PRNG_FF, PRNG_I, PRNG_J, PRNG_MAX_LEN, PRNG_Q,
        PRNG_SEED, SEED_LEN,
    },
    hasher::Hasher,
    util::ustr::{u16str, u32str},
    Sha256Hasher,
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

    pub fn set_lms_leaf_identifier(&mut self, q: u32) {
        self.lms_leaf_identifier = q;
    }

    pub fn set_child_seed(&mut self, j: u16) {
        self.child_seed = j;
    }

    pub fn seed_derive(&mut self, increment_j: bool) -> [u8; Sha256Hasher::OUTPUT_SIZE] {
        let mut buffer = [0u8; PRNG_MAX_LEN];

        buffer[PRNG_I..PRNG_I + ILEN].copy_from_slice(self.lms_tree_identifier);

        let lms_leaf_identifier = u32str(self.lms_leaf_identifier);
        buffer[PRNG_Q..PRNG_Q + 4].copy_from_slice(&lms_leaf_identifier);

        let j = u16str(self.child_seed);
        buffer[PRNG_J..PRNG_J + 2].copy_from_slice(&j);

        buffer[PRNG_FF] = 0xff;

        buffer[PRNG_SEED..PRNG_SEED + SEED_LEN].copy_from_slice(self.master_seed);

        let mut hasher = Sha256Hasher::new(); // We always use SHA256 to derive seeds

        hasher.update(&buffer[..prng_len(SEED_LEN)]);

        if increment_j {
            self.child_seed += 1;
        }

        let mut result = [0u8; Sha256Hasher::OUTPUT_SIZE];

        result.copy_from_slice(hasher.finalize().as_slice());

        result
    }
}
