use crate::extract_or_return;
use crate::hasher::Hasher;
use crate::lm_ots::parameters::LmotsAlgorithm;
use crate::{
    constants::{D_MESG, MAX_HASH_CHAIN_ITERATIONS, MAX_HASH_SIZE},
    util::{
        coef::coef,
        random::get_random,
        ustr::{str32u, u32str},
    },
};
use arrayvec::ArrayVec;
use core::usize;

#[cfg(feature = "fast_verify")]
use {
    crate::constants::{MAX_HASH_OPTIMIZATIONS, THREADS},
    std::sync::mpsc,
    std::thread,
};

use super::definitions::LmotsPrivateKey;
use super::parameters::LmotsParameter;

#[derive(Debug, Default, Clone, PartialEq)]
pub struct LmotsSignature<H: Hasher> {
    pub signature_randomizer: ArrayVec<u8, MAX_HASH_SIZE>,
    pub signature_data: ArrayVec<ArrayVec<u8, MAX_HASH_SIZE>, MAX_HASH_CHAIN_ITERATIONS>,
    pub lmots_parameter: LmotsParameter<H>,
    pub hash_iterations: u16,
}

#[derive(Clone)]
pub struct InMemoryLmotsSignature<'a, H: Hasher> {
    pub signature_randomizer: &'a [u8],
    pub signature_data: &'a [u8],
    pub lmots_parameter: LmotsParameter<H>,
}

impl<'a, H: Hasher> PartialEq<LmotsSignature<H>> for InMemoryLmotsSignature<'a, H> {
    fn eq(&self, other: &LmotsSignature<H>) -> bool {
        let first_cond = self.signature_randomizer == other.signature_randomizer.as_slice()
            && self.lmots_parameter == other.lmots_parameter;

        if !first_cond {
            return false;
        }

        let mut curr = self.signature_data;
        for x in other.signature_data.iter() {
            for y in x.iter() {
                if curr[0] != *y {
                    return false;
                }
                curr = &curr[1..];
            }
        }

        true
    }
}

impl<H: 'static + Hasher> LmotsSignature<H> {
    fn calculate_message_hash(
        private_key: &LmotsPrivateKey<H>,
        message: &[u8],
    ) -> (H, ArrayVec<u8, MAX_HASH_SIZE>) {
        let mut signature_randomizer = ArrayVec::new();

        let lmots_parameter = private_key.lmots_parameter;

        let mut hasher = lmots_parameter.get_hasher();

        for _ in 0..lmots_parameter.get_hash_function_output_size() {
            signature_randomizer.push(0u8);
        }

        get_random(signature_randomizer.as_mut_slice());

        hasher.update(&private_key.lms_tree_identifier);
        hasher.update(&private_key.lms_leaf_identifier);
        hasher.update(&D_MESG);
        hasher.update(signature_randomizer.as_slice());
        hasher.update(message);

        (hasher, signature_randomizer)
    }

    #[cfg(feature = "fast_verify")]
    fn optimize_message_hash(
        hasher: &mut H,
        lmots_parameter: &LmotsParameter<H>,
        message_randomizer: &mut [u8],
    ) {
        let mut max_hash_chain_iterations = 0;

        let (max, sum, coef_cached) = lmots_parameter.fast_verify_eval_init();

        let rx = {
            let (tx, rx) = mpsc::channel();

            for _ in 0..THREADS {
                let thread_hash_optimizations = MAX_HASH_OPTIMIZATIONS / THREADS;
                let thread_hasher = hasher.clone();
                let thread_lmots_parameter = *lmots_parameter;
                let thread_coef_cached = coef_cached.clone();
                let thread_tx = tx.clone();

                thread::spawn(move || {
                    let result = thread_optimize_message_hash::<H>(
                        thread_hash_optimizations,
                        &thread_hasher,
                        &thread_lmots_parameter,
                        max,
                        sum,
                        &thread_coef_cached,
                    );
                    thread_tx.send(result).unwrap();
                });
            }
            rx
        };

        for (hash_chain_iterations, trial_message_randomizer) in rx {
            if hash_chain_iterations > max_hash_chain_iterations {
                max_hash_chain_iterations = hash_chain_iterations;
                message_randomizer.copy_from_slice(trial_message_randomizer.as_slice());
            }
        }
    }

    fn calculate_signature(
        private_key: &LmotsPrivateKey<H>,
        message_hash_with_checksum: &ArrayVec<u8, { MAX_HASH_SIZE + 2 }>,
    ) -> ArrayVec<ArrayVec<u8, MAX_HASH_SIZE>, MAX_HASH_CHAIN_ITERATIONS> {
        let lmots_parameter = private_key.lmots_parameter;

        let mut hasher = lmots_parameter.get_hasher();

        let mut signature_data = ArrayVec::new();

        for i in 0..lmots_parameter.get_max_hash_iterations() {
            let a = coef(
                message_hash_with_checksum.as_slice(),
                i,
                lmots_parameter.get_winternitz(),
            ) as usize;
            let initial = private_key.key[i as usize].clone();
            let mut hash_chain_data = H::prepare_hash_chain_data(
                &private_key.lms_tree_identifier,
                &private_key.lms_leaf_identifier,
            );
            let result = hasher.do_hash_chain(&mut hash_chain_data, i, initial.as_slice(), 0, a);

            signature_data.push(result);
        }

        signature_data
    }

    #[cfg(feature = "fast_verify")]
    pub fn sign_fast_verify(private_key: &LmotsPrivateKey<H>, message: &mut [u8]) -> Self {
        let lmots_parameter = private_key.lmots_parameter;

        let (mut hasher, signature_randomizer) = if MAX_HASH_OPTIMIZATIONS != 0
            && message.len() > lmots_parameter.get_hash_function_output_size()
        {
            let message_end = message.len() - lmots_parameter.get_hash_function_output_size();
            let (message, mut message_randomizer) = message.split_at_mut(message_end);

            let (mut hasher, signature_randomizer) =
                LmotsSignature::<H>::calculate_message_hash(private_key, message);

            let mut message_randomizer_zero = true;
            for &byte in message_randomizer.iter() {
                if byte != 0u8 {
                    message_randomizer_zero = false;
                };
            }

            if message_randomizer_zero {
                LmotsSignature::<H>::optimize_message_hash(
                    &mut hasher,
                    &lmots_parameter,
                    &mut message_randomizer,
                );
            }

            hasher.update(message_randomizer);

            (hasher, signature_randomizer)
        } else {
            LmotsSignature::<H>::calculate_message_hash(private_key, message)
        };

        let message_hash: ArrayVec<u8, MAX_HASH_SIZE> = hasher.finalize_reset();
        let message_hash_with_checksum =
            lmots_parameter.append_checksum_to(message_hash.as_slice());

        let signature_data =
            LmotsSignature::<H>::calculate_signature(private_key, &message_hash_with_checksum);

        let mut hash_iterations = 0;
        for i in 0..lmots_parameter.get_max_hash_iterations() {
            let a = coef(
                message_hash_with_checksum.as_slice(),
                i,
                lmots_parameter.get_winternitz(),
            ) as usize;
            hash_iterations += a as u16;
        }

        LmotsSignature {
            signature_randomizer,
            signature_data,
            lmots_parameter,
            hash_iterations,
        }
    }

    pub fn sign(private_key: &LmotsPrivateKey<H>, message: &[u8]) -> Self {
        let lmots_parameter = private_key.lmots_parameter;

        let (mut hasher, signature_randomizer) =
            LmotsSignature::<H>::calculate_message_hash(private_key, message);

        let message_hash: ArrayVec<u8, MAX_HASH_SIZE> = hasher.finalize_reset();
        let message_hash_with_checksum =
            lmots_parameter.append_checksum_to(message_hash.as_slice());

        let signature_data =
            LmotsSignature::<H>::calculate_signature(private_key, &message_hash_with_checksum);

        LmotsSignature {
            signature_randomizer,
            signature_data,
            lmots_parameter,
            hash_iterations: 0,
        }
    }

    pub fn to_binary_representation(
        &self,
    ) -> ArrayVec<u8, { 4 + MAX_HASH_SIZE + (MAX_HASH_SIZE * MAX_HASH_CHAIN_ITERATIONS) }> {
        let mut result = ArrayVec::new();

        result
            .try_extend_from_slice(&u32str(self.lmots_parameter.get_type_id()))
            .unwrap();
        result
            .try_extend_from_slice(self.signature_randomizer.as_slice())
            .unwrap();

        for hash_chain_value in self.signature_data.iter() {
            for hash_chain_byte in hash_chain_value.iter() {
                result.try_extend_from_slice(&[*hash_chain_byte]).unwrap();
            }
        }

        result
    }
}

impl<'a, H: Hasher> InMemoryLmotsSignature<'a, H> {
    pub fn new(data: &'a [u8]) -> Option<Self> {
        if data.len() < 4 {
            return None;
        }

        let mut consumed_data = data;

        let lm_ots_type = str32u(&consumed_data[..4]);
        consumed_data = &consumed_data[4..];

        let lmots_parameter = extract_or_return!(LmotsAlgorithm::get_from_type(lm_ots_type));

        let lm_ots_hash_function_output_size = lmots_parameter.get_hash_function_output_size();
        let max_hash_iterations = lmots_parameter.get_max_hash_iterations();

        if data.len()
            != 4 + lm_ots_hash_function_output_size as usize * (max_hash_iterations as usize + 1)
        {
            return None;
        }

        let signature_randomizer: &'a [u8] =
            &consumed_data[..lm_ots_hash_function_output_size as usize];
        consumed_data = &consumed_data[lm_ots_hash_function_output_size as usize..];

        let signature_data: &'a [u8] =
            &consumed_data[..max_hash_iterations as usize * lm_ots_hash_function_output_size];

        let signature = Self {
            signature_randomizer,
            signature_data,
            lmots_parameter,
        };

        Some(signature)
    }

    pub fn get_signature_data(&self, index: usize) -> &[u8] {
        let step = self.lmots_parameter.get_hash_function_output_size();
        let start = step * index;
        let end = start + step;
        &self.signature_data[start..end]
    }
}

#[cfg(feature = "fast_verify")]
fn thread_optimize_message_hash<H: Hasher>(
    thread_hash_optimizations: usize,
    hasher: &H,
    lmots_parameter: &LmotsParameter<H>,
    max: u16,
    sum: u16,
    coef_cached: &ArrayVec<(usize, u16, u64), 300>,
) -> (u16, ArrayVec<u8, MAX_HASH_SIZE>) {
    let mut max_hash_chain_iterations = 0;

    let mut trial_message_randomizer_seed: ArrayVec<u8, MAX_HASH_SIZE> = ArrayVec::new();
    let mut trial_message_randomizer: ArrayVec<u8, MAX_HASH_SIZE> = ArrayVec::new();
    let mut message_randomizer: ArrayVec<u8, MAX_HASH_SIZE> = ArrayVec::new();

    for _ in 0..lmots_parameter.get_hash_function_output_size() {
        trial_message_randomizer_seed.push(0u8);
        trial_message_randomizer.push(0u8);
        message_randomizer.push(0u8);
    }

    get_random(trial_message_randomizer_seed.as_mut_slice());

    let mut hasher_message_randomizer = lmots_parameter.get_hasher();
    hasher_message_randomizer.update(&trial_message_randomizer_seed);

    for _ in 0..thread_hash_optimizations {
        let mut hasher_message_randomizer_trial = hasher_message_randomizer.clone();
        hasher_message_randomizer_trial.update(&trial_message_randomizer);
        trial_message_randomizer = hasher_message_randomizer_trial.finalize_reset();

        let mut hasher_trial = hasher.clone();
        hasher_trial.update(trial_message_randomizer.as_slice());
        let message_hash: ArrayVec<u8, MAX_HASH_SIZE> = hasher_trial.finalize_reset();

        let hash_chain_iterations =
            lmots_parameter.fast_verify_eval(message_hash.as_slice(), max, sum, coef_cached);

        if hash_chain_iterations > max_hash_chain_iterations {
            max_hash_chain_iterations = hash_chain_iterations;
            message_randomizer.copy_from_slice(trial_message_randomizer.as_slice());
        }
    }
    (max_hash_chain_iterations, message_randomizer)
}

#[cfg(test)]
mod tests {
    use arrayvec::ArrayVec;

    use crate::{
        constants::{MAX_HASH_CHAIN_ITERATIONS, MAX_HASH_SIZE},
        lm_ots::{parameters::LmotsAlgorithm, signing::InMemoryLmotsSignature},
    };

    use super::LmotsSignature;

    #[test]
    fn test_binary_representation() {
        let lmots_parameter = LmotsAlgorithm::construct_default_parameter();

        let mut signature_randomizer = ArrayVec::new();
        let mut signature_data: ArrayVec<ArrayVec<u8, MAX_HASH_SIZE>, MAX_HASH_CHAIN_ITERATIONS> =
            ArrayVec::new();

        for i in 0..lmots_parameter.get_hash_function_output_size() as usize {
            signature_randomizer.push(i as u8);
        }

        for i in 0..lmots_parameter.get_max_hash_iterations() as usize {
            signature_data.push(ArrayVec::new());
            for j in 0..lmots_parameter.get_hash_function_output_size() as usize {
                signature_data[i].push(j as u8);
            }
        }

        let signature = LmotsSignature {
            signature_randomizer,
            signature_data,
            lmots_parameter,
            hash_iterations: 0,
        };

        let binary_rep = signature.to_binary_representation();
        let deserialized_signature = InMemoryLmotsSignature::new(binary_rep.as_slice())
            .expect("Deserialization must succeed.");

        assert!(deserialized_signature == signature);
    }
}
