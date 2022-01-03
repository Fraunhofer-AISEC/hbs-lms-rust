use core::{
    convert::TryFrom,
    fmt::Debug,
    ops::{Deref, DerefMut},
};
use tinyvec::ArrayVec;

use crate::constants::{winternitz_chain::*, MAX_HASH_SIZE};

pub mod sha256;
pub mod shake256;

pub struct HashChainData {
    data: [u8; ITER_MAX_LEN],
}

impl Deref for HashChainData {
    type Target = [u8; ITER_MAX_LEN];

    fn deref(&self) -> &Self::Target {
        &self.data
    }
}

impl DerefMut for HashChainData {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.data
    }
}

/**
 *
 * This trait is used inside the library to generate hashes. A standard software implementation exists as `Sha256`.
 * It can be used to outsource calculations to hardware accelerators.
 *
 *
 * Implements PartialEq, although it makes no sense to compare two hasher.
 * But with that we can derive PartialEq automatically for our tests.
 * */
pub trait HashChain: Debug + Default + Clone + PartialEq + Send + Sync {
    const OUTPUT_SIZE: u16;
    const BLOCK_SIZE: u16;

    fn update(&mut self, data: &[u8]);
    fn chain(self, data: &[u8]) -> Self;
    fn finalize(self) -> ArrayVec<[u8; MAX_HASH_SIZE]>;
    fn finalize_reset(&mut self) -> ArrayVec<[u8; MAX_HASH_SIZE]>;

    fn prepare_hash_chain_data(
        lms_tree_identifier: &[u8],
        lms_leaf_identifier: &[u8],
    ) -> HashChainData {
        let mut hc_data = HashChainData {
            data: [0u8; ITER_MAX_LEN],
        };
        hc_data[ITER_I..ITER_Q].copy_from_slice(lms_tree_identifier);
        hc_data[ITER_Q..ITER_K].copy_from_slice(lms_leaf_identifier);
        hc_data
    }

    fn do_hash_chain(
        &mut self,
        hc_data: &mut HashChainData,
        hash_chain_id: u16,
        initial_value: &[u8],
        from: usize,
        to: usize,
    ) -> ArrayVec<[u8; MAX_HASH_SIZE]> {
        hc_data[ITER_K..ITER_J].copy_from_slice(&hash_chain_id.to_be_bytes());
        hc_data[ITER_PREV..].copy_from_slice(initial_value);

        self.do_actual_hash_chain(hc_data, from, to);

        ArrayVec::try_from(&hc_data[ITER_PREV..]).unwrap()
    }

    fn do_actual_hash_chain(&mut self, hc_data: &mut HashChainData, from: usize, to: usize) {
        for j in from..to {
            hc_data[ITER_J] = j as u8;
            // We assume that the hasher is fresh initialized on the first round
            self.update(&hc_data.data);
            let temp_hash = self.finalize_reset();
            hc_data[ITER_PREV..].copy_from_slice(temp_hash.as_slice());
        }
    }
}
