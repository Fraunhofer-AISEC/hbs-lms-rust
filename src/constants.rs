use core::mem::size_of;
use tinyvec::ArrayVec;

include!(concat!(env!("OUT_DIR"), "/constants.rs"));

pub const ILEN: usize = 16;
pub const SEED_LEN: usize = 32;

pub type LmsTreeIdentifier = [u8; ILEN];
pub type Seed = [u8; SEED_LEN];
pub type LmsLeafIdentifier = [u8; 4];

type FvcMax = u16;
type FvcSum = u16;
type FvcCoef = (usize, u16, u64); // (index, shift, mask)
pub type FastVerifyCached = (FvcMax, FvcSum, ArrayVec<[FvcCoef; MAX_HASH_CHAIN_COUNT]>);

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
pub const SEED_SIGNATURE_RANDOMIZER_SEED: u16 = 0xabba;

pub const fn prng_len(seed_len: usize) -> usize {
    23 + seed_len
}

pub const LMS_LEAF_IDENTIFIERS_SIZE: usize = 8;
pub const REF_IMPL_MAX_ALLOWED_HSS_LEVELS: usize = 8;
pub const REFERENCE_IMPL_PRIVATE_KEY_SIZE: usize =
    LMS_LEAF_IDENTIFIERS_SIZE + REF_IMPL_MAX_ALLOWED_HSS_LEVELS + size_of::<Seed>();

pub const MAX_HASH_SIZE: usize = 32;
pub const MAX_HASH_BLOCK_SIZE: usize = 64;

pub const PRNG_MAX_LEN: usize = prng_len(MAX_HASH_SIZE);

pub const HASH_CHAIN_COUNT_W1: u16 = 265;
pub const HASH_CHAIN_COUNT_W2: u16 = 133;
pub const HASH_CHAIN_COUNT_W4: u16 = 67;
pub const HASH_CHAIN_COUNT_W8: u16 = 34;
pub const MAX_HASH_CHAIN_COUNT: usize = get_hash_chain_count(MIN_WINTERNITZ_PARAMETER);

pub const MAX_LMOTS_SIGNATURE_LENGTH: usize =
    lmots_signature_length(MAX_HASH_SIZE, MAX_HASH_CHAIN_COUNT);

pub const MAX_LMS_PUBLIC_KEY_LENGTH: usize = lms_public_key_length(MAX_HASH_SIZE);
pub const MAX_LMS_SIGNATURE_LENGTH: usize =
    lms_signature_length(MAX_HASH_SIZE, MAX_HASH_CHAIN_COUNT, MAX_TREE_HEIGHT);

pub const MAX_HSS_PUBLIC_KEY_LENGTH: usize = size_of::<u32>()       // HSS Level
        + lms_public_key_length(MAX_HASH_SIZE); // Root LMS PublicKey
pub const MAX_HSS_SIGNED_PUBLIC_KEY_LENGTH: usize =
    hss_signed_public_key_length(MAX_HASH_SIZE, MAX_HASH_CHAIN_COUNT, MAX_TREE_HEIGHT);
pub const MAX_HSS_SIGNATURE_LENGTH: usize = get_hss_signature_length();

pub const fn get_hash_chain_count(winternitz_parameter: usize) -> usize {
    match winternitz_parameter {
        1 => HASH_CHAIN_COUNT_W1 as usize,
        2 => HASH_CHAIN_COUNT_W2 as usize,
        4 => HASH_CHAIN_COUNT_W4 as usize,
        8 => HASH_CHAIN_COUNT_W8 as usize,
        _ => panic!("Invalid Winternitz parameter. Allowed is: 1, 2, 4 or 8"),
    }
}

pub const fn lmots_signature_length(hash_size: usize, hash_chain_count: usize) -> usize {
    size_of::<u32>()                                                // LMOTS Parameter TypeId
        + hash_size                                                 // Signature Randomizer
        + (hash_size * hash_chain_count) // Signature Data
}

pub const fn lms_public_key_length(hash_size: usize) -> usize {
    size_of::<u32>()                                                // LMS Parameter TypeId
        + size_of::<u32>()                                          // LMOTS Parameter TypeId
        + size_of::<LmsTreeIdentifier>()                            // LMS TreeIdentifier
        + hash_size // PublicKey
}

pub const fn lms_signature_length(
    hash_size: usize,
    hash_chain_count: usize,
    tree_height: usize,
) -> usize {
    size_of::<u32>()                                                // LMS Leaf Identifier
        + lmots_signature_length(hash_size, hash_chain_count)       // LMOTS Signature
        + size_of::<u32>()                                          // LMS Parameter TypeId
        + (hash_size * tree_height) // Authentication Path
}

pub const fn hss_signed_public_key_length(
    hash_size: usize,
    hash_chain_count: usize,
    tree_height: usize,
) -> usize {
    lms_signature_length(hash_size, hash_chain_count, tree_height)  // LMS Signature
        + MAX_LMS_PUBLIC_KEY_LENGTH // LMS PublicKey
}

pub const fn get_hss_signature_length() -> usize {
    let mut length = size_of::<u32>();

    let mut level = MAX_ALLOWED_HSS_LEVELS - 1;
    while level > 0 {
        length += hss_signed_public_key_length(
            MAX_HASH_SIZE,
            get_hash_chain_count(WINTERNITZ_PARAMETERS[level]),
            TREE_HEIGHTS[level],
        );
        level -= 1;
    }

    length
        + lms_signature_length(
            MAX_HASH_SIZE,
            get_hash_chain_count(WINTERNITZ_PARAMETERS[0]),
            TREE_HEIGHTS[0],
        )
}

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
