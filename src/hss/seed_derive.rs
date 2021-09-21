use crate::{
    constants::{
        prg_len, LmsTreeIdentifier, Seed, ILEN, PRG_FF, PRG_I, PRG_J, PRG_MAX_LEN, PRG_Q, PRG_SEED,
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
        let mut buffer = [0u8; PRG_MAX_LEN];

        buffer[PRG_I..PRG_I + ILEN].copy_from_slice(self.i);

        let q = u32str(self.q);
        buffer[PRG_Q..PRG_Q + 4].copy_from_slice(&q);

        let j = u16str(self.j);
        buffer[PRG_J..PRG_J + 2].copy_from_slice(&j);

        buffer[PRG_FF] = 0xff;

        buffer[PRG_SEED..PRG_SEED + SEED_LEN].copy_from_slice(self.master_seed);

        let mut hasher = Sha256Hasher::new(); // We always use SHA256 to derive seeds

        hasher.update(&buffer[..prg_len(SEED_LEN)]);

        if increment_j {
            self.j += 1;
        }

        let mut result = [0u8; Sha256Hasher::OUTPUT_SIZE];

        result.copy_from_slice(hasher.finalize().as_slice());

        result
    }
}
