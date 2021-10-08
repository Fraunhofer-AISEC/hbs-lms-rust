use crate::{
    constants::{DAUX_D, DAUX_PREFIX_LEN, D_DAUX, MAX_H, MAX_HASH, MIN_SUBTREE},
    hasher::Hasher,
    util::{
        dynamic_array::DynamicArray,
        ustr::{str32u, u32str},
    },
    LmsParameter,
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
    pub data: [Option<&'a mut [u8]>; MAX_H + 1],
    pub level: u32,
    pub hmac: &'a mut [u8],
}

pub fn hss_optimal_aux_level<H: Hasher>(
    mut max_length: usize,
    lms_parameter: LmsParameter<H>,
    actual_len: Option<&mut usize>,
) -> AuxLevel {
    let h0 = lms_parameter.get_height();
    let size_hash = lms_parameter.get_m();

    if max_length < AUX_DATA_HASHES + size_hash {
        if let Some(actual_len) = actual_len {
            *actual_len = 1;
        }
        return 0;
    }

    let orig_max_length = max_length;
    max_length -= AUX_DATA_HASHES + size_hash;

    let mut aux_level: AuxLevel = 0;

    let substree_size = hss_smallest_subtree_size(h0, 0, size_hash);
    let mut level = h0 as u32 % substree_size;

    if level == 0 {
        level = substree_size;
    }

    for level in (level..h0 as u32).step_by(substree_size as usize) {
        let len_this_level = size_hash << level;

        if max_length >= len_this_level {
            max_length -= len_this_level;
            aux_level |= 0x80000000 | (1 << level);
        } else {
            break;
        }
    }

    if let Some(actual_len) = actual_len {
        *actual_len = orig_max_length - max_length;
    }

    aux_level
}

pub fn hss_smallest_subtree_size(_tree_height: u8, _i: usize, _n: usize) -> u32 {
    if MIN_SUBTREE > 2 {
        panic!("We assume that a subtree of size 2 is allowed");
    }
    2
}

pub fn hss_expand_aux_data<'a, H: Hasher>(
    aux_data: Option<&'a mut [u8]>,
    seed: Option<&'a [u8]>,
) -> Option<MutableExpandedAuxData<'a>> {
    let size_hash = H::OUTPUT_SIZE;

    let mut expanded_aux_data: MutableExpandedAuxData = Default::default();

    aux_data.as_ref()?;
    let mut aux_data = aux_data.unwrap();

    if aux_data[AUX_DATA_MARKER] == NO_AUX_DATA {
        return None;
    }

    let mut index = 4;
    let mut aux_level = str32u(&aux_data[0..index]) as u64; // u64 is used otherwise we could not AND it with 0x7ffffffff
    expanded_aux_data.level = aux_level as u32;
    aux_level &= 0x7ffffffff;

    // Check if data is valid
    if let Some(seed) = seed {
        for h in 0..(MAX_H + 1) {
            if (aux_level >> h) & 1 != 0 {
                index += size_hash << h;
            }
        }

        let expected_len = index + size_hash;

        if expected_len > aux_data.len() {
            return None;
        }

        if aux_data.len() < 4 + size_hash {
            return None;
        }

        let mut key = [0u8; MAX_HASH];
        compute_seed_derive::<H>(&mut key, seed);

        let mut expected_mac = [0u8; MAX_HASH];
        compute_hmac::<H>(&mut expected_mac, &mut key, aux_data);

        if expected_mac[..size_hash] != aux_data[index..(index + size_hash)] {
            return None;
        }
    }

    index = 4;
    aux_data = &mut aux_data[index..];

    for h in 0..(MAX_H + 1) {
        if (aux_level >> h) & 1 != 0 {
            index = size_hash << h;
            let (left, rest) = aux_data.split_at_mut(index);

            expanded_aux_data.data[h] = Some(left);
            aux_data = rest;
        }
    }
    expanded_aux_data.hmac = aux_data;

    Some(expanded_aux_data)
}

pub fn hss_get_aux_data_len<H: Hasher>(max_length: usize, lms_parameter: LmsParameter<H>) -> usize {
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
        let levels = u32str(aux_level);
        aux_data[0..4].copy_from_slice(&levels);
    }
}

pub fn hss_is_aux_data_used(aux_data: &[u8]) -> bool {
    aux_data[AUX_DATA_MARKER] != NO_AUX_DATA
}

pub fn hss_save_aux_data<H: Hasher>(
    data: &mut MutableExpandedAuxData,
    index: usize,
    cur_val: &[u8],
) {
    // We need to calculate the level of the tree and the offset from the beginning
    let level = core::mem::size_of::<usize>() * 8 - index.leading_zeros() as usize - 1;
    let lms_leaf_identifier: u32 = index as u32 - 2u32.pow(level as u32);

    if data.data[level as usize].is_none() {
        return;
    }

    let size_hash = H::OUTPUT_SIZE;

    let dest = data.data[level as usize].as_mut().unwrap();
    let start_index = size_hash * lms_leaf_identifier as usize;
    let end_index = start_index + size_hash;
    dest[start_index..end_index].copy_from_slice(cur_val);
}

pub fn hss_finalize_aux_data<H: Hasher>(data: &mut MutableExpandedAuxData, seed: &[u8]) {
    let mut aux_seed = [0u8; MAX_HASH];

    compute_seed_derive::<H>(&mut aux_seed, seed);

    let mut hasher = compute_hmac_ipad::<H>(&mut aux_seed);
    hasher.update(&data.level.to_be_bytes());

    for i in 0..MAX_H {
        if let Some(x) = data.data[i].as_mut() {
            hasher.update(x);
        }
    }

    compute_hmac_opad::<H>(&mut hasher, data.hmac, &mut aux_seed);
}

pub fn hss_extract_aux_data<H: Hasher>(
    aux: &MutableExpandedAuxData,
    index: usize,
) -> Option<DynamicArray<u8, MAX_HASH>> {
    // We need to calculate the level of the tree and the offset from the beginning
    let level = core::mem::size_of::<usize>() * 8 - index.leading_zeros() as usize - 1;
    let lms_leaf_identifier: u32 = index as u32 - 2u32.pow(level as u32);

    aux.data[level as usize].as_ref()?;

    let src = aux.data[level as usize].as_ref().unwrap();

    let hash_size = H::OUTPUT_SIZE;

    let start_index = lms_leaf_identifier as usize * hash_size;
    let end_index = start_index + hash_size;

    if src[start_index..end_index] == [0u8; MAX_HASH] {
        return None;
    }

    let mut result = DynamicArray::new();

    result.append(&src[start_index..end_index]);

    Some(result)
}

fn compute_seed_derive<H: Hasher>(result: &mut [u8], seed: &[u8]) {
    let mut prefix = [0u8; DAUX_PREFIX_LEN];

    prefix[DAUX_D] = (D_DAUX >> 8) as u8;
    prefix[DAUX_D + 1] = (D_DAUX & 0xff) as u8;

    let mut hasher = H::get_hasher();

    hasher.update(&prefix[..]);
    hasher.update(seed);

    result.copy_from_slice(hasher.finalize().as_slice());
}

fn xor_key(key: &mut [u8], xor_val: u8) {
    for val in key {
        *val ^= xor_val;
    }
}

fn compute_hmac_ipad<H: Hasher>(key: &mut [u8]) -> H {
    let size_hash = H::OUTPUT_SIZE;
    let block_size = H::BLOCK_SIZE;

    let mut hasher = H::get_hasher();

    xor_key(key, IPAD);
    hasher.update(key);

    for _ in size_hash..block_size {
        hasher.update(&[IPAD]);
    }

    hasher
}

fn compute_hmac_opad<H: Hasher>(hasher: &mut H, dest: &mut [u8], key: &mut [u8]) {
    let size_hash = H::OUTPUT_SIZE;
    let block_size = H::BLOCK_SIZE;

    dest.copy_from_slice(hasher.finalize_reset().as_slice());

    xor_key(key, IPAD ^ OPAD);
    hasher.update(key);

    for _ in size_hash..block_size {
        hasher.update(&[OPAD]);
    }

    hasher.update(dest);

    dest.copy_from_slice(hasher.finalize_reset().as_slice());

    xor_key(key, OPAD);
}

fn compute_hmac<H: Hasher>(dest: &mut [u8], key: &mut [u8], data: &[u8]) {
    let mut hasher = compute_hmac_ipad::<H>(key);

    hasher.update(data);

    compute_hmac_opad::<H>(&mut hasher, dest, key);
}
