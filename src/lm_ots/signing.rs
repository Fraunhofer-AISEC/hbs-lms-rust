use crate::{
    constants::{D_MESG, MAX_HASH_SIZE, MAX_LMOTS_SIGNATURE_LENGTH, MAX_NUM_WINTERNITZ_CHAINS},
    hasher::HashChain,
    lm_ots::parameters::LmotsAlgorithm,
    util::{coef::coef, helper::read_and_advance},
};

use core::convert::TryInto;
use tinyvec::ArrayVec;

#[cfg(feature = "fast_verify")]
use {
    crate::constants::{
        FastVerifyCached, MAX_HASH_OPTIMIZATIONS, MAX_LMS_PUBLIC_KEY_LENGTH, THREADS,
    },
    core::convert::TryFrom,
    crossbeam::{channel::unbounded, scope},
    rand::{rngs::OsRng, RngCore},
};

use super::definitions::LmotsPrivateKey;
use super::parameters::LmotsParameter;

#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct LmotsSignature<H: HashChain> {
    pub signature_randomizer: ArrayVec<[u8; MAX_HASH_SIZE]>,
    pub signature_data: ArrayVec<[ArrayVec<[u8; MAX_HASH_SIZE]>; MAX_NUM_WINTERNITZ_CHAINS]>,
    pub lmots_parameter: LmotsParameter<H>,
    pub hash_iterations: u16,
}

#[derive(Clone)]
pub struct InMemoryLmotsSignature<'a, H: HashChain> {
    pub signature_randomizer: &'a [u8],
    pub signature_data: &'a [u8],
    pub lmots_parameter: LmotsParameter<H>,
}

impl<'a, H: HashChain> PartialEq<LmotsSignature<H>> for InMemoryLmotsSignature<'a, H> {
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

impl<H: HashChain> LmotsSignature<H> {
    fn calculate_message_hash(
        private_key: &LmotsPrivateKey<H>,
        signature_randomizer: &ArrayVec<[u8; MAX_HASH_SIZE]>,
        message: &[u8],
    ) -> H {
        let lmots_parameter = private_key.lmots_parameter;

        lmots_parameter
            .get_hasher()
            .chain(private_key.lms_tree_identifier)
            .chain(private_key.lms_leaf_identifier)
            .chain(D_MESG)
            .chain(signature_randomizer)
            .chain(message)
    }

    #[cfg(feature = "fast_verify")]
    fn calculate_message_hash_fast_verify(
        private_key: &LmotsPrivateKey<H>,
        signature_randomizer: &mut ArrayVec<[u8; MAX_HASH_SIZE]>,
        message: Option<&[u8]>,
        message_mut: Option<&mut [u8]>,
    ) -> H {
        let lmots_parameter = private_key.lmots_parameter;

        let mut hasher = lmots_parameter
            .get_hasher()
            .chain(private_key.lms_tree_identifier)
            .chain(private_key.lms_leaf_identifier)
            .chain(D_MESG);

        if let Some(message_mut) = message_mut {
            let message_end = message_mut.len() - H::OUTPUT_SIZE as usize;
            let (message_mut, message_randomizer) = message_mut.split_at_mut(message_end);

            hasher.update(signature_randomizer);
            hasher.update(message_mut);

            optimize_message_hash(&hasher, &lmots_parameter, message_randomizer, None);

            hasher.update(message_randomizer);
        } else {
            optimize_message_hash(&hasher, &lmots_parameter, signature_randomizer, message);

            hasher.update(signature_randomizer.as_slice());
            hasher.update(message.unwrap());
        }
        hasher
    }

    fn calculate_signature(
        private_key: &LmotsPrivateKey<H>,
        message_hash_with_checksum: &ArrayVec<[u8; MAX_HASH_SIZE + 2]>,
    ) -> ArrayVec<[ArrayVec<[u8; MAX_HASH_SIZE]>; MAX_NUM_WINTERNITZ_CHAINS]> {
        let lmots_parameter = private_key.lmots_parameter;

        let mut hasher = lmots_parameter.get_hasher();

        let mut signature_data = ArrayVec::new();

        for i in 0..lmots_parameter.get_num_winternitz_chains() {
            let a = coef(
                message_hash_with_checksum.as_slice(),
                i,
                lmots_parameter.get_winternitz(),
            ) as usize;
            let initial = private_key.key[i as usize];
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
        signature_randomizer: &ArrayVec<[u8; MAX_HASH_SIZE]>,
        message: &[u8],
    ) -> Self {
        let mut hasher =
            LmotsSignature::<H>::calculate_message_hash(private_key, signature_randomizer, message);
        LmotsSignature::<H>::sign_core(private_key, &mut hasher, signature_randomizer)
    }

    #[cfg(feature = "fast_verify")]
    pub fn sign_fast_verify(
        private_key: &LmotsPrivateKey<H>,
        signature_randomizer: &mut ArrayVec<[u8; MAX_HASH_SIZE]>,
        message: Option<&[u8]>,
        message_mut: Option<&mut [u8]>,
    ) -> Self {
        let mut hasher = LmotsSignature::<H>::calculate_message_hash_fast_verify(
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
        signature_randomizer: &ArrayVec<[u8; MAX_HASH_SIZE]>,
    ) -> Self {
        let lmots_parameter = private_key.lmots_parameter;

        let message_hash: ArrayVec<[u8; MAX_HASH_SIZE]> = hasher.finalize_reset();
        let message_hash_with_checksum =
            lmots_parameter.append_checksum_to(message_hash.as_slice());

        let signature_data =
            LmotsSignature::<H>::calculate_signature(private_key, &message_hash_with_checksum);

        let hash_iterations = (0..lmots_parameter.get_num_winternitz_chains()).fold(0, |sum, i| {
            sum + coef(
                message_hash_with_checksum.as_slice(),
                i,
                lmots_parameter.get_winternitz(),
            ) as u16
        });

        LmotsSignature {
            signature_randomizer: *signature_randomizer,
            signature_data,
            lmots_parameter,
            hash_iterations,
        }
    }

    pub fn to_binary_representation(&self) -> ArrayVec<[u8; MAX_LMOTS_SIGNATURE_LENGTH]> {
        let mut result = ArrayVec::new();

        result.extend_from_slice(&(self.lmots_parameter.get_type_id()).to_be_bytes());
        assert_eq!(
            self.signature_randomizer.len(),
            self.lmots_parameter.get_hash_function_output_size()
        );
        result.extend_from_slice(self.signature_randomizer.as_slice());

        for hash_chain_value in self.signature_data.iter() {
            for hash_chain_byte in hash_chain_value.iter() {
                result.extend_from_slice(&[*hash_chain_byte]);
            }
        }

        result
    }
}

impl<'a, H: HashChain> InMemoryLmotsSignature<'a, H> {
    pub fn new(data: &'a [u8]) -> Option<Self> {
        let mut index = 0;

        let lmots_parameter = LmotsAlgorithm::get_from_type::<H>(u32::from_be_bytes(
            read_and_advance(data, 4, &mut index).try_into().unwrap(),
        ))
        .unwrap();

        let signature_randomizer = read_and_advance(data, H::OUTPUT_SIZE as usize, &mut index);

        let signature_data = read_and_advance(
            data,
            (H::OUTPUT_SIZE * lmots_parameter.get_num_winternitz_chains()) as usize,
            &mut index,
        );

        Some(Self {
            signature_randomizer,
            signature_data,
            lmots_parameter,
        })
    }

    pub fn get_signature_data(&self, index: usize) -> &[u8] {
        let step = self.lmots_parameter.get_hash_function_output_size();
        let start = step * index;
        let end = start + step;
        &self.signature_data[start..end]
    }
}

#[cfg(feature = "fast_verify")]
fn optimize_message_hash<H: HashChain>(
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

    let rx = {
        let (tx, rx) = unbounded();

        scope(|s| {
            for _ in 0..THREADS {
                let tx = tx.clone();
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

    let mut max_hash_iterations = 0;
    for (hash_iterations, trial_randomizer) in rx.iter() {
        if hash_iterations > max_hash_iterations {
            max_hash_iterations = hash_iterations;
            randomizer.copy_from_slice(trial_randomizer.as_slice());
        }
    }
}

#[cfg(feature = "fast_verify")]
fn thread_optimize_message_hash<H: HashChain>(
    hasher: &H,
    lmots_parameter: &LmotsParameter<H>,
    fast_verify_cached: &FastVerifyCached,
    message: &ArrayVec<[u8; MAX_LMS_PUBLIC_KEY_LENGTH]>,
) -> (u16, ArrayVec<[u8; MAX_HASH_SIZE]>) {
    let mut max_hash_iterations = 0;

    let mut trial_randomizer: ArrayVec<[u8; MAX_HASH_SIZE]> = ArrayVec::new();
    let mut randomizer: ArrayVec<[u8; MAX_HASH_SIZE]> = ArrayVec::new();

    for _ in 0..lmots_parameter.get_hash_function_output_size() {
        trial_randomizer.push(0u8);
        randomizer.push(0u8);
    }

    OsRng.fill_bytes(trial_randomizer.as_mut_slice());

    for _ in 0..MAX_HASH_OPTIMIZATIONS / THREADS {
        trial_randomizer = lmots_parameter
            .get_hasher()
            .chain(trial_randomizer)
            .finalize();

        let message_hash: ArrayVec<[u8; MAX_HASH_SIZE]> = hasher
            .clone()
            .chain(trial_randomizer.as_slice())
            .chain(message)
            .finalize();

        let hash_iterations =
            lmots_parameter.fast_verify_eval(message_hash.as_slice(), fast_verify_cached);

        if hash_iterations > max_hash_iterations {
            max_hash_iterations = hash_iterations;
            randomizer.copy_from_slice(trial_randomizer.as_slice());
        }
    }
    (max_hash_iterations, randomizer)
}

#[cfg(test)]
mod tests {
    use tinyvec::ArrayVec;

    use crate::{
        constants::{MAX_HASH_SIZE, MAX_NUM_WINTERNITZ_CHAINS},
        hasher::{
            sha256::{Sha256_128, Sha256_192, Sha256_256},
            shake256::{Shake256_128, Shake256_192, Shake256_256},
        },
        lm_ots::{
            parameters::LmotsAlgorithm, signing::InMemoryLmotsSignature, signing::LmotsSignature,
        },
    };

    macro_rules! generate_test {
        ($name:ident, $hash_chain:ty) => {
            #[test]
            fn $name() {
                let lmots_parameter = LmotsAlgorithm::construct_default_parameter::<$hash_chain>();

                let mut signature_randomizer = ArrayVec::new();
                let mut signature_data: ArrayVec<
                    [ArrayVec<[u8; MAX_HASH_SIZE]>; MAX_NUM_WINTERNITZ_CHAINS],
                > = ArrayVec::new();

                for i in 0..lmots_parameter.get_hash_function_output_size() as usize {
                    signature_randomizer.push(i as u8);
                }

                for i in 0..lmots_parameter.get_num_winternitz_chains() as usize {
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

                // check signature len
                let output_size = lmots_parameter.get_hash_function_output_size() as usize;
                let hash_chain_count = lmots_parameter.get_num_winternitz_chains() as usize;
                assert_eq!(binary_rep.len(), 4 + output_size * (hash_chain_count + 1));

                let deserialized_signature = InMemoryLmotsSignature::new(binary_rep.as_slice())
                    .expect("Deserialization must succeed.");

                assert!(deserialized_signature == signature);
            }
        };
    }

    generate_test!(lmots_sha256_n32_binary_representation_test, Sha256_256);

    generate_test!(lmots_sha256_n24_binary_representation_test, Sha256_192);

    generate_test!(lmots_sha256_n16_binary_representation_test, Sha256_128);

    generate_test!(lmots_shake256_n32_binary_representation_test, Shake256_128);

    generate_test!(lmots_shake256_n24_binary_representation_test, Shake256_192);

    generate_test!(lmots_shake256_n16_binary_representation_test, Shake256_256);
}
