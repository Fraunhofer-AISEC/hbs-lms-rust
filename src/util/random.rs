#[cfg(target_arch = "x86_64")]
use rand::{rngs::OsRng, RngCore};

#[cfg(target_arch = "x86_64")]
pub fn get_random(dest: &mut [u8]) {
    OsRng.fill_bytes(dest);
}

#[cfg(not(target_arch = "x86_64"))]
pub fn get_random(_dest: &mut [u8]) {
    panic!("Random number generator is not supported on this platform.")
}
