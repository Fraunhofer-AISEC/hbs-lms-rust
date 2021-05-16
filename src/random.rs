use rand::{RngCore, rngs::OsRng};

pub fn get_random(dest: &mut [u8]) {
    OsRng.fill_bytes(dest);
}