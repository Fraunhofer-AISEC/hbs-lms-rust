use rand::{rngs::OsRng, RngCore};

pub fn get_random(dest: &mut [u8]) {
    OsRng.fill_bytes(dest);
}
