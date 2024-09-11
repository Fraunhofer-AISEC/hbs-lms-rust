use core::mem::size_of;
use tinyvec::ArrayVec;

include!(concat!(env!("OUT_DIR"), "/constants.rs"));

pub const ILEN: usize = 16;
pub const MAX_SEED_LEN: usize = 32;

pub type Node = ArrayVec<[u8; MAX_HASH_SIZE]>;
pub type LmsTreeIdentifier = [u8; ILEN];
pub type LmsLeafIdentifier = [u8; 4];

type FvcMax = u16;
type FvcSum = u16;
type FvcCoef = (usize, u16, u64); // (index, shift, mask)
pub type FastVerifyCached = (
    FvcMax,
    FvcSum,
    ArrayVec<[FvcCoef; MAX_NUM_WINTERNITZ_CHAINS]>,
);

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
pub const SEED_SIGNATURE_RANDOMIZER_SEED: u16 = !2;

pub const fn prng_len(seed_len: usize) -> usize {
    23 + seed_len
}

pub const HSS_COMPRESSED_USED_LEAFS_SIZE: usize = size_of::<u64>();
pub const REF_IMPL_MAX_ALLOWED_HSS_LEVELS: usize = 8;

pub const SST_SIGNING_ENTITY_IDX_SIZE: usize = size_of::<u8>();
pub const SST_L0_TOP_DIV_SIZE: usize = size_of::<u8>();
pub const SST_SIZE: usize = SST_SIGNING_ENTITY_IDX_SIZE + SST_L0_TOP_DIV_SIZE;

pub const SST_IMPL_MAX_PRIVATE_KEY_SIZE: usize =
    SST_SIZE + HSS_COMPRESSED_USED_LEAFS_SIZE + REF_IMPL_MAX_ALLOWED_HSS_LEVELS + MAX_SEED_LEN;
pub const REF_IMPL_MAX_PRIVATE_KEY_SIZE: usize =
    HSS_COMPRESSED_USED_LEAFS_SIZE + REF_IMPL_MAX_ALLOWED_HSS_LEVELS + MAX_SEED_LEN;
// TODO Rework if `const_trait_impl` is in stable
pub const IMPL_MAX_PRIVATE_KEY_SIZE: usize = SST_IMPL_MAX_PRIVATE_KEY_SIZE;

pub const MAX_HASH_SIZE: usize = 32;
pub const MAX_HASH_BLOCK_SIZE: usize = 64;

pub const PRNG_MAX_LEN: usize = prng_len(MAX_HASH_SIZE);

pub const MAX_NUM_WINTERNITZ_CHAINS: usize =
    get_num_winternitz_chains(MIN_WINTERNITZ_PARAMETER, MAX_HASH_SIZE);

pub const MAX_LMOTS_SIGNATURE_LENGTH: usize =
    lmots_signature_length(MAX_HASH_SIZE, MAX_NUM_WINTERNITZ_CHAINS);

pub const MAX_LMS_PUBLIC_KEY_LENGTH: usize = lms_public_key_length(MAX_HASH_SIZE);
pub const MAX_LMS_SIGNATURE_LENGTH: usize =
    lms_signature_length(MAX_HASH_SIZE, MAX_NUM_WINTERNITZ_CHAINS, MAX_TREE_HEIGHT);

pub const MAX_HSS_PUBLIC_KEY_LENGTH: usize = size_of::<u32>()       // HSS Level
        + lms_public_key_length(MAX_HASH_SIZE); // Root LMS PublicKey
pub const MAX_HSS_SIGNED_PUBLIC_KEY_LENGTH: usize =
    hss_signed_public_key_length(MAX_HASH_SIZE, MAX_NUM_WINTERNITZ_CHAINS, MAX_TREE_HEIGHT);
pub const MAX_HSS_SIGNATURE_LENGTH: usize = get_hss_signature_length();

pub const MAX_SSTS_L0_TOP_DIV: u32 = 8; // top division height for Single-Subtree-scheme
pub const MAX_SSTS_SIGNING_ENTITIES: usize = 2usize.pow(MAX_SSTS_L0_TOP_DIV);

/// Calculated using the formula from RFC 8554 Appendix B
/// https://datatracker.ietf.org/doc/html/rfc8554#appendix-B
const NUM_WINTERNITZ_CHAINS: [usize; 12] = [136, 200, 265, 68, 101, 133, 35, 51, 67, 18, 26, 34];

// RFC 8554: "p"; see terminology: "single Winternitz chain", "number of independent Winternitz chains"
pub const fn get_num_winternitz_chains(winternitz_parameter: usize, output_size: usize) -> usize {
    let w_i = match winternitz_parameter {
        1 => 0usize,
        2 => 1usize,
        4 => 2usize,
        8 => 3usize,
        _ => panic!("Invalid Winternitz parameter. Allowed is: 1, 2, 4 or 8"),
    };

    let o_i = match output_size {
        16 => 0usize,
        24 => 1usize,
        32 => 2usize,
        _ => panic!("Invalid Output Size. Allowed is: 16, 24 or 32"),
    };

    NUM_WINTERNITZ_CHAINS[w_i * 3 + o_i]
}

pub const fn lmots_signature_length(hash_size: usize, num_winternitz_chains: usize) -> usize {
    size_of::<u32>()                                                // LMOTS Parameter TypeId
        + hash_size                                                 // Signature Randomizer
        + (hash_size * num_winternitz_chains) // Signature Data
}

pub const fn lms_public_key_length(hash_size: usize) -> usize {
    size_of::<u32>()                                                // LMS Parameter TypeId
        + size_of::<u32>()                                          // LMOTS Parameter TypeId
        + size_of::<LmsTreeIdentifier>()                            // LMS TreeIdentifier
        + hash_size // PublicKey
}

pub const fn lms_signature_length(
    hash_size: usize,
    num_winternitz_chains: usize,
    tree_height: usize,
) -> usize {
    size_of::<u32>()                                                // LMS Leaf Identifier
        + lmots_signature_length(hash_size, num_winternitz_chains)       // LMOTS Signature
        + size_of::<u32>()                                          // LMS Parameter TypeId
        + (hash_size * tree_height) // Authentication Path
}

pub const fn hss_signed_public_key_length(
    hash_size: usize,
    num_winternitz_chains: usize,
    tree_height: usize,
) -> usize {
    lms_signature_length(hash_size, num_winternitz_chains, tree_height)  // LMS Signature
        + MAX_LMS_PUBLIC_KEY_LENGTH // LMS PublicKey
}

pub const fn get_hss_signature_length() -> usize {
    let mut length = size_of::<u32>();

    let mut level = MAX_ALLOWED_HSS_LEVELS - 1;
    while level > 0 {
        length += hss_signed_public_key_length(
            MAX_HASH_SIZE,
            get_num_winternitz_chains(WINTERNITZ_PARAMETERS[level], MAX_HASH_SIZE),
            TREE_HEIGHTS[level],
        );
        level -= 1;
    }

    length
        + lms_signature_length(
            MAX_HASH_SIZE,
            get_num_winternitz_chains(WINTERNITZ_PARAMETERS[0], MAX_HASH_SIZE),
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

#[cfg(test)]
mod tests {
    use crate::constants::get_num_winternitz_chains;

    #[test]
    fn test_get_num_winternitz_chains() {
        assert_eq!(get_num_winternitz_chains(1, 32), 265);
        assert_eq!(get_num_winternitz_chains(2, 32), 133);
        assert_eq!(get_num_winternitz_chains(4, 32), 67);
        assert_eq!(get_num_winternitz_chains(8, 32), 34);
        assert_eq!(get_num_winternitz_chains(1, 24), 200);
        assert_eq!(get_num_winternitz_chains(2, 24), 101);
        assert_eq!(get_num_winternitz_chains(4, 24), 51);
        assert_eq!(get_num_winternitz_chains(8, 24), 26);
        assert_eq!(get_num_winternitz_chains(1, 16), 136);
        assert_eq!(get_num_winternitz_chains(2, 16), 68);
        assert_eq!(get_num_winternitz_chains(4, 16), 35);
        assert_eq!(get_num_winternitz_chains(8, 16), 18);
    }
}
