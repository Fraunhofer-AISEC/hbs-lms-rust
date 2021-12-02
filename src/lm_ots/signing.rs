use crate::extract_or_return;
use crate::hasher::Hasher;
use crate::lm_ots::parameters::LmotsAlgorithm;
use crate::{
    constants::{
        D_MESG, MAX_HASH_CHAIN_ITERATIONS, MAX_HASH_OPTIMIZATIONS, MAX_HASH_SIZE,
        MAX_LMS_PUBLIC_KEY_LENGTH, THREADS,
    },
    util::{
        coef::coef,
        random::get_random,
        ustr::{str32u, u32str},
    },
};
use arrayvec::ArrayVec;
use core::convert::TryFrom;

#[cfg(feature = "std")]
use crossbeam::{channel::unbounded, scope};

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

impl<H: Hasher> LmotsSignature<H> {
    fn calculate_message_hash(
        private_key: &LmotsPrivateKey<H>,
        signature_randomizer: Option<ArrayVec<u8, MAX_HASH_SIZE>>,
        message: &[u8],
    ) -> (H, ArrayVec<u8, MAX_HASH_SIZE>) {
        let lmots_parameter = private_key.lmots_parameter;

        let signature_randomizer = signature_randomizer.unwrap_or_else(|| {
            let mut randomizer = ArrayVec::new();
            for _ in 0..lmots_parameter.get_hash_function_output_size() {
                randomizer.push(0u8);
            }
            get_random(randomizer.as_mut_slice());
            randomizer
        });

        let hasher = lmots_parameter
            .get_hasher()
            .chain(&private_key.lms_tree_identifier)
            .chain(&private_key.lms_leaf_identifier)
            .chain(&D_MESG)
            .chain(signature_randomizer.as_slice())
            .chain(message);

        (hasher, signature_randomizer)
    }

    fn calculate_message_hash_fast_verify(
        private_key: &LmotsPrivateKey<H>,
        signature_randomizer: Option<ArrayVec<u8, MAX_HASH_SIZE>>,
        message: Option<&[u8]>,
        message_mut: Option<&mut [u8]>,
    ) -> (H, ArrayVec<u8, MAX_HASH_SIZE>) {
        let lmots_parameter = private_key.lmots_parameter;

        let mut signature_randomizer = signature_randomizer.unwrap_or_else(|| {
            let mut randomizer = ArrayVec::new();
            for _ in 0..lmots_parameter.get_hash_function_output_size() {
                randomizer.push(0u8);
            }
            get_random(randomizer.as_mut_slice());
            randomizer
        });

        let mut hasher = lmots_parameter
            .get_hasher()
            .chain(&private_key.lms_tree_identifier)
            .chain(&private_key.lms_leaf_identifier)
            .chain(&D_MESG);

        if let Some(message_mut) = message_mut {
            let message_end = message_mut.len() - H::OUTPUT_SIZE as usize;
            let (message_mut, message_randomizer) = message_mut.split_at_mut(message_end);

            hasher.update(signature_randomizer.as_slice());
            hasher.update(message_mut);

            optimize_message_hash(&hasher, &lmots_parameter, message_randomizer, None);

            hasher.update(message_randomizer);
        } else {
            optimize_message_hash(
                &hasher,
                &lmots_parameter,
                &mut signature_randomizer,
                message,
            );

            hasher.update(signature_randomizer.as_slice());
            hasher.update(message.unwrap());
        }
        (hasher, signature_randomizer)
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

    pub fn sign(
        private_key: &LmotsPrivateKey<H>,
        signature_randomizer: Option<ArrayVec<u8, MAX_HASH_SIZE>>,
        message: &[u8],
    ) -> Self {
        let (mut hasher, signature_randomizer) =
            LmotsSignature::<H>::calculate_message_hash(private_key, signature_randomizer, message);
        LmotsSignature::<H>::sign_core(private_key, &mut hasher, signature_randomizer)
    }

    pub fn sign_fast_verify(
        private_key: &LmotsPrivateKey<H>,
        signature_randomizer: Option<ArrayVec<u8, MAX_HASH_SIZE>>,
        message: Option<&[u8]>,
        message_mut: Option<&mut [u8]>,
    ) -> Self {
        let (mut hasher, signature_randomizer) =
            LmotsSignature::<H>::calculate_message_hash_fast_verify(
                private_key,
                signature_randomizer,
                message,
                message_mut,
            );
        LmotsSignature::<H>::sign_core(private_key, &mut hasher, signature_randomizer)
    }

    fn sign_core(
        private_key: &LmotsPrivateKey<H>,
        hasher: &mut H,
        signature_randomizer: ArrayVec<u8, MAX_HASH_SIZE>,
    ) -> Self {
        let lmots_parameter = private_key.lmots_parameter;

        let message_hash: ArrayVec<u8, MAX_HASH_SIZE> = hasher.finalize_reset();
        let message_hash_with_checksum =
            lmots_parameter.append_checksum_to(message_hash.as_slice());

        let signature_data =
            LmotsSignature::<H>::calculate_signature(private_key, &message_hash_with_checksum);

        let hash_iterations = (0..lmots_parameter.get_max_hash_iterations()).fold(0, |sum, i| {
            sum + coef(
                message_hash_with_checksum.as_slice(),
                i,
                lmots_parameter.get_winternitz(),
            ) as u16
        });

        LmotsSignature {
            signature_randomizer,
            signature_data,
            lmots_parameter,
            hash_iterations,
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

fn optimize_message_hash<H: Hasher>(
    hasher: &H,
    lmots_parameter: &LmotsParameter<H>,
    randomizer: &mut [u8],
    message: Option<&[u8]>,
) {
    let message = message
        .map(|message: &[u8]| ArrayVec::try_from(message).unwrap())
        .unwrap_or_default();

    assert_eq!(message, ArrayVec::new());
    let fast_verify_cached = lmots_parameter.fast_verify_eval_init();

    #[cfg(feature = "std")]
    {
        let rx = {
            let (tx, rx) = unbounded();

            scope(|s| {
                for _ in 0..THREADS {
                    let tx = tx.clone();
                    let fast_verify_cached = fast_verify_cached.clone();
                    let message = message.clone();
                    s.spawn(move |_| {
                        tx.send(thread_optimize_message_hash::<H>(
                            hasher,
                            lmots_parameter,
                            &fast_verify_cached,
                            &message,
                        ))
                        .unwrap()
                    });
                }
            })
            .unwrap();
            rx
        };

        let mut max_hash_chain_iterations = 0;
        for (hash_chain_iterations, trial_randomizer) in rx.iter() {
            if hash_chain_iterations > max_hash_chain_iterations {
                max_hash_chain_iterations = hash_chain_iterations;
                randomizer.copy_from_slice(trial_randomizer.as_slice());
            }
        }
    }

    #[cfg(not(feature = "std"))]
    {
        let (_, trial_randomizer) = thread_optimize_message_hash::<H>(
            hasher,
            lmots_parameter,
            &fast_verify_cached,
            &message,
        );

        randomizer.copy_from_slice(trial_randomizer.as_slice());
    }
}

fn thread_optimize_message_hash<H: Hasher>(
    hasher: &H,
    lmots_parameter: &LmotsParameter<H>,
    fast_verify_cached: &(u16, u16, ArrayVec<(usize, u16, u64), 300>),
    message: &ArrayVec<u8, MAX_LMS_PUBLIC_KEY_LENGTH>,
) -> (u16, ArrayVec<u8, MAX_HASH_SIZE>) {
    let mut max_hash_chain_iterations = 0;

    let mut trial_randomizer: ArrayVec<u8, MAX_HASH_SIZE> = ArrayVec::new();
    let mut randomizer: ArrayVec<u8, MAX_HASH_SIZE> = ArrayVec::new();

    for _ in 0..lmots_parameter.get_hash_function_output_size() {
        trial_randomizer.push(0u8);
        randomizer.push(0u8);
    }

    get_random(trial_randomizer.as_mut_slice());

    for _ in 0..MAX_HASH_OPTIMIZATIONS / THREADS {
        trial_randomizer = lmots_parameter
            .get_hasher()
            .chain(&trial_randomizer)
            .finalize();

        let message_hash: ArrayVec<u8, MAX_HASH_SIZE> = hasher
            .clone()
            .chain(trial_randomizer.as_slice())
            .chain(message)
            .finalize();

        let hash_chain_iterations =
            lmots_parameter.fast_verify_eval(message_hash.as_slice(), fast_verify_cached);

        if hash_chain_iterations > max_hash_chain_iterations {
            max_hash_chain_iterations = hash_chain_iterations;
            randomizer.copy_from_slice(trial_randomizer.as_slice());
        }
    }
    (max_hash_chain_iterations, randomizer)
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
