use crate::{constants::MAX_N, util::dynamic_array::DynamicArray};

pub mod sha256;

pub trait Hasher {
    fn update(&mut self, data: &[u8]);
    fn finalize(self) -> DynamicArray<u8, MAX_N>;
    fn finalize_reset(&mut self) -> DynamicArray<u8, MAX_N>;
}
