#[cfg(feature = "std")]
use rand::{rngs::OsRng, RngCore};

#[cfg(feature = "std")]
pub fn get_random(dest: &mut [u8]) {
    OsRng.fill_bytes(dest);
}

#[cfg(not(feature = "std"))]
pub fn get_random(_dest: &mut [u8]) {
    panic!("Random number generator is not supported on this platform.")
}
