use crate::{
    constants::{
        prng_len, LmsTreeIdentifier, Seed, ILEN, PRNG_FF, PRNG_I, PRNG_J, PRNG_MAX_LEN, PRNG_Q, PRNG_SEED,
        SEED_LEN,
    },
    hasher::Hasher,
    util::ustr::{u16str, u32str},
    Sha256Hasher,
};

pub struct SeedDerive<'a> {
    master_seed: &'a Seed,
    i: &'a LmsTreeIdentifier,
    q: u32,
    j: u16,
}

impl<'a> SeedDerive<'a> {
    pub fn new(seed: &'a Seed, i: &'a LmsTreeIdentifier) -> Self {
        SeedDerive {
            master_seed: seed,
            i,
            q: 0,
            j: 0,
        }
    }

    pub fn set_q(&mut self, q: u32) {
        self.q = q;
    }

    pub fn set_j(&mut self, j: u16) {
        self.j = j;
    }

    pub fn seed_derive(&mut self, increment_j: bool) -> [u8; Sha256Hasher::OUTPUT_SIZE] {
        let mut buffer = [0u8; PRNG_MAX_LEN];

        buffer[PRNG_I..PRNG_I + ILEN].copy_from_slice(self.i);

        let lms_leaf_identifier = u32str(self.q);
        buffer[PRNG_Q..PRNG_Q + 4].copy_from_slice(&lms_leaf_identifier);

        let j = u16str(self.j);
        buffer[PRNG_J..PRNG_J + 2].copy_from_slice(&j);

        buffer[PRNG_FF] = 0xff;

        buffer[PRNG_SEED..PRNG_SEED + SEED_LEN].copy_from_slice(self.master_seed);

        let mut hasher = Sha256Hasher::new(); // We always use SHA256 to derive seeds

        hasher.update(&buffer[..prng_len(SEED_LEN)]);

        if increment_j {
            self.j += 1;
        }

        let mut result = [0u8; Sha256Hasher::OUTPUT_SIZE];

        result.copy_from_slice(hasher.finalize().as_slice());

        result
    }
}
