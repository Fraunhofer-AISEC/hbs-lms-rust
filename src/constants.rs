use core::mem::size_of;

include!(concat!(env!("OUT_DIR"), "/constants.rs"));

pub const ILEN: usize = 16;
pub const SEED_LEN: usize = 32;

pub type LmsTreeIdentifier = [u8; ILEN];
pub type Seed = [u8; SEED_LEN];
pub type LmsLeafIdentifier = [u8; 4];

pub const D_PBLC: [u8; 2] = [0x80, 0x80];
pub const D_MESG: [u8; 2] = [0x81, 0x81];
pub const D_LEAF: [u8; 2] = [0x82, 0x82];
pub const D_INTR: [u8; 2] = [0x83, 0x83];

pub const TOPSEED_SEED: usize = 23;
pub const TOPSEED_LEN: usize = TOPSEED_SEED + 32;
pub const TOPSEED_D: usize = 20;
pub const TOPSEED_WHICH: usize = 22;
pub const D_TOPSEED: u16 = 0xfefe;

pub const PRNG_I: usize = 0;
pub const PRNG_Q: usize = 16;
pub const PRNG_J: usize = 20;
pub const PRNG_FF: usize = 22;
pub const PRNG_SEED: usize = 23;

pub const SEED_CHILD_SEED: u16 = !1;

pub const fn prng_len(seed_len: usize) -> usize {
    23 + seed_len
}

pub const MAX_HASH_SIZE: usize = 32;

pub const PRNG_MAX_LEN: usize = prng_len(MAX_HASH_SIZE);

pub const MAX_HASH_CHAIN_ITERATIONS: usize = 265;
pub const MAX_TREE_HEIGHT: usize = 25;

pub const REFERENCE_IMPL_PRIVATE_KEY_SIZE: usize = 8 + MAX_ALLOWED_HSS_LEVELS + size_of::<Seed>();

pub const MAX_LMS_PUBLIC_KEY_LENGTH: usize = lms_public_key_length(MAX_HASH_SIZE);
pub const MAX_LMS_SIGNATURE_LENGTH: usize = lms_signature_length(
    MAX_HASH_SIZE,
    MAX_HASH_CHAIN_ITERATIONS,
    MAX_HASH_SIZE,
    MAX_TREE_HEIGHT,
);

pub const fn lms_signature_length(
    lm_ots_hash_function_output_size: usize,
    max_hash_iterations: usize,
    lms_hash_function_output_size: usize,
    tree_height: usize,
) -> usize {
    4 + (4
        + lm_ots_hash_function_output_size
        + (lm_ots_hash_function_output_size * max_hash_iterations))
        + 4
        + (lms_hash_function_output_size * tree_height)
}

pub const fn lms_public_key_length(lms_hash_output_size: usize) -> usize {
    4 + 4 + 16 + lms_hash_output_size
}

pub const MAX_ALLOWED_HSS_LEVELS: usize = 8;

pub const MAX_HSS_SIGNATURE_LENGTH: usize = (4
    + (4 + MAX_HASH_SIZE + (MAX_HASH_SIZE * MAX_HASH_CHAIN_ITERATIONS))
    + 4
    + (MAX_HASH_SIZE * MAX_TREE_HEIGHT))
    * MAX_ALLOWED_HSS_LEVELS;

pub const MIN_SUBTREE: usize = 2; /* All subtrees (other than the root subtree) have at least 2 levels */

pub const DAUX_D: usize = 20;
pub const DAUX_PREFIX_LEN: usize = 22; /* Not counting the seed value */
pub const D_DAUX: u16 = 0xfdfd;

pub mod winternitz_chain {
    use super::MAX_HASH_SIZE;

    pub const ITER_I: usize = 0;
    pub const ITER_Q: usize = 16;
    pub const ITER_K: usize = 20;
    pub const ITER_J: usize = 22;
    pub const ITER_PREV: usize = 23;

    pub const fn iter_len(hash_len: usize) -> usize {
        ITER_PREV + hash_len
    }

    pub const ITER_MAX_LEN: usize = iter_len(MAX_HASH_SIZE);
}
