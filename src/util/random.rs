#[cfg(all(feature = "std", feature = "fast_verify"))]
use rand::{rngs::OsRng, RngCore};

#[cfg(all(feature = "std", feature = "fast_verify"))]
pub fn get_random(dest: &mut [u8]) {
    OsRng.fill_bytes(dest);
}

#[cfg(all(not(feature = "std"), feature = "fast_verify"))]
pub fn get_random(_dest: &mut [u8]) {
    panic!("Random number generator is not supported on this platform.")
}
