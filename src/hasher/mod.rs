use crate::{
    constants::MAX_HASH,
    util::{
        dynamic_array::DynamicArray,
        ustr::{u16str, u8str},
    },
};

pub mod sha256;

// Implement PartialEq, although it makes no sense to compare two hasher.
// But with that we can derive PartialEq automatically for our tests.
pub trait Hasher: Default + Clone + PartialEq {
    const OUTPUT_SIZE: usize;
    const BLOCK_SIZE: usize;
    fn get_hasher() -> Self;
    fn update(&mut self, data: &[u8]);
    fn finalize(self) -> DynamicArray<u8, MAX_HASH>;
    fn finalize_reset(&mut self) -> DynamicArray<u8, MAX_HASH>;

    fn do_hash_chain(
        &mut self,
        I: &[u8],
        q: &[u8],
        i: u16,
        from: usize,
        to: usize,
        start: &mut [u8],
    ) {
        for j in from..to {
            self.update(I);
            self.update(q);
            self.update(&u16str(i));
            self.update(&u8str(j as u8));
            self.update(start);
            start.copy_from_slice(self.finalize_reset().as_slice());
        }
    }
}
