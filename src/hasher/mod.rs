use arrayvec::ArrayVec;
use core::convert::TryFrom;

use crate::{
    constants::{winternitz_chain::*, MAX_HASH_SIZE},
    util::ustr::u16str,
};

pub mod sha256;
pub mod shake256;

pub struct HashChainData([u8; ITER_MAX_LEN]);

/**
 *
 * This trait is used inside the library to generate hashes. A standard software implementation exists as `Sha256Hasher`.
 * It can be used to outsource calculations to hardware accelerators.
 *
 *
 * Implements PartialEq, although it makes no sense to compare two hasher.
 * But with that we can derive PartialEq automatically for our tests.
 * */
pub trait Hasher: Default + Clone + PartialEq + Send {
    const OUTPUT_SIZE: u16;
    const BLOCK_SIZE: u16;
    fn get_hasher() -> Self;
    fn update(&mut self, data: &[u8]);
    fn finalize(self) -> ArrayVec<u8, MAX_HASH_SIZE>;
    fn finalize_reset(&mut self) -> ArrayVec<u8, MAX_HASH_SIZE>;

    fn prepare_hash_chain_data(
        lms_tree_identifier: &[u8],
        lms_leaf_identifier: &[u8],
    ) -> HashChainData {
        let mut hash_chain_data = HashChainData([0u8; ITER_MAX_LEN]);
        hash_chain_data.0[ITER_I..ITER_Q].copy_from_slice(lms_tree_identifier);
        hash_chain_data.0[ITER_Q..ITER_K].copy_from_slice(lms_leaf_identifier);
        hash_chain_data
    }

    fn do_hash_chain(
        &mut self,
        hash_chain_data: &mut HashChainData,
        hash_chain_id: u16,
        initial_value: &[u8],
        from: usize,
        to: usize,
    ) -> ArrayVec<u8, MAX_HASH_SIZE> {
        let temp = &mut hash_chain_data.0;

        temp[ITER_K..ITER_J].copy_from_slice(&u16str(hash_chain_id));
        temp[ITER_PREV..].copy_from_slice(initial_value);

        self.do_actual_hash_chain(temp, from, to);

        ArrayVec::try_from(&temp[ITER_PREV..]).unwrap()
    }

    fn do_actual_hash_chain(&mut self, temp: &mut [u8], from: usize, to: usize) {
        for j in from..to {
            temp[ITER_J] = j as u8;
            // We assume that the hasher is fresh initialized on the first round
            self.update(temp);
            let temp_hash = self.finalize_reset();
            temp[ITER_PREV..].copy_from_slice(temp_hash.as_slice());
        }
    }
}
