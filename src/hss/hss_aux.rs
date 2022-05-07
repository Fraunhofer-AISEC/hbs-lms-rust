use core::convert::TryInto;
use subtle::ConstantTimeEq;
use tinyvec::TinyVec;

use crate::{
    constants::{
        DAUX_D, DAUX_PREFIX_LEN, D_DAUX, MAX_HASH_BLOCK_SIZE, MAX_HASH_SIZE, MAX_TREE_HEIGHT,
        MIN_SUBTREE,
    },
    hasher::HashChain,
    lms::parameters::LmsParameter,
    util::helper::read_and_advance,
};

/**
The implementation of aux data is mainly copied from the reference implementation in C (https://github.com/cisco/hash-sigs)
For comments see the original source code.
*/

type AuxLevel = u32;

const AUX_DATA_MARKER: usize = 0;
const NO_AUX_DATA: u8 = 0x00;
const AUX_DATA_HASHES: usize = 4;

const IPAD: u8 = 0x36;
const OPAD: u8 = 0x5c;

#[derive(Default)]
pub struct MutableExpandedAuxData<'a> {
    pub data: [Option<&'a mut [u8]>; MAX_TREE_HEIGHT + 1],
    pub level: u32,
    pub hmac: &'a mut [u8],
}

pub fn hss_optimal_aux_level<H: HashChain>(
    mut max_length: usize,
    lms_parameter: LmsParameter<H>,
    actual_len: Option<&mut usize>,
) -> AuxLevel {
    let mut aux_level = AuxLevel::default();

    let size_hash = lms_parameter.get_hash_function_output_size();
    let orig_max_length = max_length;

    if max_length < AUX_DATA_HASHES + size_hash {
        if let Some(actual_len) = actual_len {
            *actual_len = 1;
        }
        return 0;
    }
    max_length -= AUX_DATA_HASHES + size_hash;

    let h0 = lms_parameter.get_tree_height().into();
    for level in (1..=h0).rev().step_by(MIN_SUBTREE) {
        let len_this_level = size_hash << level;

        if max_length >= len_this_level {
            max_length -= len_this_level;
            aux_level |= 0x80000000 | (1 << level);
        }
    }

    if let Some(actual_len) = actual_len {
        *actual_len = orig_max_length - max_length;
    }

    aux_level
}

pub fn hss_expand_aux_data<'a, H: HashChain>(
    aux_data: Option<&'a mut [u8]>,
    seed: Option<&'a [u8]>,
) -> Option<MutableExpandedAuxData<'a>> {
    let mut index = 0;

    let mut expanded_aux_data: MutableExpandedAuxData = Default::default();

    let mut aux_data = aux_data.unwrap();

    if aux_data[AUX_DATA_MARKER] == NO_AUX_DATA {
        return None;
    }

    // REMARK: Reference implementation treats that as u64 and ANDs it with 0x7ffffffffL after its stored in expanded_aux_data
    // However in our opinion that should make no difference, because we only read 4 bytes.
    expanded_aux_data.level = u32::from_be_bytes(
        read_and_advance(aux_data, 4, &mut index)
            .try_into()
            .unwrap(),
    );

    const LEN_LAYER_SIZES: usize = 1 + MAX_TREE_HEIGHT;
    let mut layer_sizes: TinyVec<[usize; LEN_LAYER_SIZES]> =
        TinyVec::from([0usize; LEN_LAYER_SIZES]);
    for index in 0..layer_sizes.capacity() {
        if (expanded_aux_data.level >> index) & 1 == 0 {
            continue;
        }
        layer_sizes[index] = (H::OUTPUT_SIZE as usize) << index;
    }

    // Check if data is valid
    if let Some(seed) = seed {
        let len_aux_data = index + layer_sizes.iter().sum::<usize>();
        let (aux_data, aux_data_mac) = aux_data.split_at(len_aux_data);

        let key = compute_seed_derive::<H>(seed);
        if !bool::from(compute_hmac::<H>(&key, aux_data).ct_eq(aux_data_mac)) {
            return None;
        }
    }

    aux_data = &mut aux_data[index..];

    for (index, layer_size) in layer_sizes
        .iter()
        .enumerate()
        .filter(|(_, size)| **size != 0)
    {
        let (data, data_rest) = aux_data.split_at_mut(*layer_size);

        expanded_aux_data.data[index] = Some(data);
        aux_data = data_rest;
    }
    expanded_aux_data.hmac = aux_data;

    Some(expanded_aux_data)
}

pub fn hss_get_aux_data_len<H: HashChain>(
    max_length: usize,
    lms_parameter: LmsParameter<H>,
) -> usize {
    let mut len = 0;

    if hss_optimal_aux_level(max_length, lms_parameter, Some(&mut len)) == 0 {
        return 1;
    }

    len
}

pub fn hss_store_aux_marker(aux_data: &mut [u8], aux_level: AuxLevel) {
    if aux_level == 0 {
        aux_data[AUX_DATA_MARKER] = NO_AUX_DATA;
    } else {
        let levels = aux_level.to_be_bytes();
        aux_data[0..4].copy_from_slice(&levels);
    }
}

pub fn hss_is_aux_data_used(aux_data: &[u8]) -> bool {
    aux_data[AUX_DATA_MARKER] != NO_AUX_DATA
}

pub fn hss_save_aux_data<H: HashChain>(
    data: &mut MutableExpandedAuxData,
    index: usize,
    cur_val: &[u8],
) {
    // We need to calculate the level of the tree and the offset from the beginning
    let level = core::mem::size_of::<usize>() * 8 - index.leading_zeros() as usize - 1;
    if data.data[level].is_none() {
        return;
    }

    let lms_leaf_identifier: usize = index - 2u32.pow(level as u32) as usize;
    let start_index = lms_leaf_identifier * H::OUTPUT_SIZE as usize;
    let end_index = start_index + H::OUTPUT_SIZE as usize;

    let dest = data.data[level].as_mut().unwrap();
    dest[start_index..end_index].copy_from_slice(cur_val);
}

pub fn hss_finalize_aux_data<H: HashChain>(data: &mut MutableExpandedAuxData, seed: &[u8]) {
    let aux_seed = compute_seed_derive::<H>(seed);

    let mut hasher = compute_hmac_ipad::<H>(&aux_seed).chain(&data.level.to_be_bytes());

    for i in 0..MAX_TREE_HEIGHT {
        if let Some(x) = data.data[i].as_mut() {
            hasher.update(x);
        }
    }

    data.hmac
        .copy_from_slice(compute_hmac_opad::<H>(&mut hasher, &aux_seed).as_slice());
}

pub fn hss_extract_aux_data<H: HashChain>(
    aux: &MutableExpandedAuxData,
    index: usize,
) -> Option<TinyVec<[u8; MAX_HASH_SIZE]>> {
    // We need to calculate the level of the tree and the offset from the beginning
    let level = core::mem::size_of::<usize>() * 8 - index.leading_zeros() as usize - 1;
    let lms_leaf_identifier: u32 = index as u32 - 2u32.pow(level as u32);

    aux.data[level as usize].as_ref()?;

    let src = aux.data[level as usize].as_ref().unwrap();

    let hash_size = H::OUTPUT_SIZE as usize;

    let start_index = lms_leaf_identifier as usize * hash_size;
    let end_index = start_index + hash_size;

    if src[start_index..end_index] == [0u8; MAX_HASH_SIZE] {
        return None;
    }

    let mut result = TinyVec::new();

    result.extend_from_slice(&src[start_index..end_index]);

    Some(result)
}

fn compute_seed_derive<H: HashChain>(seed: &[u8]) -> TinyVec<[u8; MAX_HASH_SIZE]> {
    let mut prefix = [0u8; DAUX_PREFIX_LEN];

    prefix[DAUX_D] = (D_DAUX >> 8) as u8;
    prefix[DAUX_D + 1] = (D_DAUX & 0xff) as u8;

    H::default().chain(&prefix[..]).chain(seed).finalize()
}

fn compute_hmac_ipad<H: HashChain>(key: &[u8]) -> H {
    const IPAD_ARRAY: [u8; MAX_HASH_BLOCK_SIZE] = [IPAD; MAX_HASH_BLOCK_SIZE];

    let key = key
        .iter()
        .map(|byte| byte ^ IPAD)
        .collect::<TinyVec<[u8; MAX_HASH_SIZE]>>();

    H::default()
        .chain(&key)
        .chain(&IPAD_ARRAY[H::OUTPUT_SIZE.into()..H::BLOCK_SIZE.into()])
}

fn compute_hmac_opad<H: HashChain>(hasher: &mut H, key: &[u8]) -> TinyVec<[u8; MAX_HASH_SIZE]> {
    const OPAD_ARRAY: [u8; MAX_HASH_BLOCK_SIZE] = [OPAD; MAX_HASH_BLOCK_SIZE];

    let buffer = hasher.finalize_reset();

    let key = key
        .iter()
        .map(|byte| byte ^ OPAD)
        .collect::<TinyVec<[u8; MAX_HASH_SIZE]>>();

    H::default()
        .chain(&key)
        .chain(&OPAD_ARRAY[H::OUTPUT_SIZE.into()..H::BLOCK_SIZE.into()])
        .chain(&buffer)
        .finalize_reset()
}

fn compute_hmac<H: HashChain>(key: &[u8], data: &[u8]) -> TinyVec<[u8; MAX_HASH_SIZE]> {
    let mut hasher = compute_hmac_ipad::<H>(key).chain(data);
    compute_hmac_opad::<H>(&mut hasher, key)
}

#[cfg(test)]
mod tests {
    use rand::{rngs::OsRng, RngCore};

    use crate::hasher::sha256::Sha256;
    use crate::{
        constants::MAX_HASH_SIZE,
        hss::{hss_aux::hss_expand_aux_data, hss_keygen},
        HssParameter, LmotsAlgorithm, LmsAlgorithm, Seed,
    };

    #[test]
    #[should_panic(expected = "expand_aux_data should return None!")]
    fn expand_aux_data_with_forged_aux_data() {
        let mut seed = Seed::default();
        OsRng.fill_bytes(&mut seed);
        type H = Sha256;

        let lmots = LmotsAlgorithm::LmotsW2;
        let lms = LmsAlgorithm::LmsH5;
        let parameters = [HssParameter::new(lmots, lms), HssParameter::new(lmots, lms)];

        let mut aux_data = [0u8; 1_000];
        let aux_slice: &mut &mut [u8] = &mut &mut aux_data[..];

        let _ =
            hss_keygen::<H>(&parameters, &seed, Some(aux_slice)).expect("Should generate HSS keys");

        aux_slice[2 * MAX_HASH_SIZE - 1] ^= 1;

        hss_expand_aux_data::<H>(Some(aux_slice), Some(&seed))
            .expect("expand_aux_data should return None!");
    }
}
