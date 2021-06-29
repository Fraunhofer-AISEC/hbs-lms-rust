use rand::{rngs::OsRng, RngCore};

#[cfg(target_arch = "x86_64")]
pub fn get_random(dest: &mut [u8]) {
    OsRng.fill_bytes(dest);
}
