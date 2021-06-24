use crate::constants::MAX_N;

pub mod sha256;

pub trait Hasher {
    fn update(&mut self, data: &[u8]);
    fn finalize(self) -> [u8; MAX_N];
    fn finalize_reset(&mut self) -> [u8; MAX_N];
}
