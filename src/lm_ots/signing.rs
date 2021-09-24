use crate::extract_or_return;
use crate::hasher::Hasher;
use crate::lm_ots::parameters::LmotsAlgorithm;
use crate::util::dynamic_array::DynamicArray;
use crate::{
    constants::{D_MESG, MAX_HASH, MAX_P},
    util::{
        coef::coef,
        random::get_random,
        ustr::{str32u, u32str},
    },
};
use core::usize;

use super::definitions::LmotsPrivateKey;
use super::parameters::LmotsParameter;

#[derive(Debug, Default, Clone, PartialEq)]
pub struct LmotsSignature<H: Hasher> {
    pub signature_randomizer: DynamicArray<u8, MAX_HASH>,
    pub signature_data: DynamicArray<DynamicArray<u8, MAX_HASH>, MAX_P>,
    pub lmots_parameter: LmotsParameter<H>,
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
    pub fn sign(private_key: &LmotsPrivateKey<H>, message: &[u8]) -> Self {
        let mut signature_randomizer = DynamicArray::new();

        let lmots_parameter = private_key.lmots_parameter;

        let mut hasher = lmots_parameter.get_hasher();

        signature_randomizer.set_size(lmots_parameter.get_n() as usize);

        get_random(signature_randomizer.as_mut_slice());

        hasher.update(&private_key.lms_tree_identifier);
        hasher.update(&private_key.lms_leaf_identifier);
        hasher.update(&D_MESG);
        hasher.update(signature_randomizer.as_slice());
        hasher.update(message);

        let message_hash: DynamicArray<u8, MAX_HASH> = hasher.finalize_reset();
        let message_hash_with_checksum =
            lmots_parameter.append_checksum_to(message_hash.as_slice());

        let mut signature_data: DynamicArray<DynamicArray<u8, MAX_HASH>, MAX_P> =
            DynamicArray::new();

        for i in 0..lmots_parameter.get_p() {
            let a = coef(
                message_hash_with_checksum.as_slice(),
                i as u64,
                lmots_parameter.get_winternitz() as u64,
            ) as usize;
            let initial = private_key.key[i as usize].clone();
            let mut hash_chain_data = H::prepare_hash_chain_data(
                &private_key.lms_tree_identifier,
                &private_key.lms_leaf_identifier,
            );
            let result = hasher.do_hash_chain(&mut hash_chain_data, i, initial.as_slice(), 0, a);

            signature_data.push(result);
        }

        LmotsSignature {
            signature_randomizer,
            signature_data,
            lmots_parameter,
        }
    }

    pub fn to_binary_representation(
        &self,
    ) -> DynamicArray<u8, { 4 + MAX_HASH + (MAX_HASH * MAX_P) }> {
        let mut result = DynamicArray::new();

        result.append(&u32str(self.lmots_parameter.get_type()));
        result.append(self.signature_randomizer.as_slice());

        for x in self.signature_data.iter() {
            for y in x.iter() {
                result.append(&[*y]);
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

        let n = lmots_parameter.get_n();
        let p = lmots_parameter.get_p();

        if data.len() != 4 + n as usize * (p as usize + 1) {
            return None;
        }

        let signature_randomizer: &'a [u8] = &consumed_data[..n as usize];
        consumed_data = &consumed_data[n as usize..];

        let signature_data: &'a [u8] = &consumed_data[..p as usize * n];

        let signature = Self {
            signature_randomizer,
            signature_data,
            lmots_parameter,
        };

        Some(signature)
    }

    pub fn get_y(&self, index: usize) -> &[u8] {
        let step = self.lmots_parameter.get_n();
        let start = step * index;
        let end = start + step;
        &self.signature_data[start..end]
    }
}

#[cfg(test)]
mod tests {
    use crate::{
        constants::{MAX_HASH, MAX_P},
        lm_ots::{parameters::LmotsAlgorithm, signing::InMemoryLmotsSignature},
        util::dynamic_array::DynamicArray,
    };

    use super::LmotsSignature;

    #[test]
    fn test_binary_representation() {
        let lmots_parameter = LmotsAlgorithm::construct_default_parameter();

        let mut signature_randomizer = DynamicArray::new();
        let mut signature_data: DynamicArray<DynamicArray<u8, MAX_HASH>, MAX_P> =
            DynamicArray::new();

        for i in 0..lmots_parameter.get_n() as usize {
            signature_randomizer.push(i as u8);
        }

        for i in 0..lmots_parameter.get_p() as usize {
            signature_data.push(DynamicArray::new());
            for j in 0..lmots_parameter.get_n() as usize {
                signature_data[i].push(j as u8);
            }
        }

        let signature = LmotsSignature {
            signature_randomizer,
            signature_data,
            lmots_parameter,
        };

        let binary_rep = signature.to_binary_representation();
        let deserialized_signature = InMemoryLmotsSignature::new(binary_rep.as_slice())
            .expect("Deserialization must succeed.");

        assert!(deserialized_signature == signature);
    }
}
