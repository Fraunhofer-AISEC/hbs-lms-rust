use crate::{signature::Error, HssParameter, Sha256_256};
use tinyvec::ArrayVec;
use crate::{
    constants::{
        //LmsTreeIdentifier,
        MAX_HASH_SIZE,
    },
    hasher::HashChain,
    //hss::definitions::HssPrivateKey, //seed_derive::SeedDerive}
    //LmotsAlgorithm, LmsAlgorithm,
    hss::reference_impl_private_key::SeedAndLmsTreeIdentifier,
    hss::reference_impl_private_key::Seed,
};

// parameters
pub fn gen_sst_subtree<H: HashChain>(top_height: u8, entity_idx: u8, hss_param: &HssParameter<H>, seed: &Seed<H>)
    -> Result<ArrayVec<[u8; MAX_HASH_SIZE]>, Error> {
    // @TODO: nyi
    // 1. we need an HSS SigningKey/VerifyingKey ; pretend to have a full LMS here to fulfill
    //    param. requirements for existing functions.
    //    A difference is that the different signing entities will use different seeds,
    //    but that shouldn't have any repercussions
    // 2. get_tree_element(idx, LmsPrivateKey, aux_data)
    //    w/o aux data first
    //    - idx
    //      - either 1 , but that would mean we consider as a whole tree
    //      - or rather the correct idx in the whole SSTS/LMS; we know our "sub-tree ID";
    //          then each sub-tree's seed is used as a "start a left-most leaf" seed

    let mut node_value = ArrayVec::from([0u8; MAX_HASH_SIZE]);
    // @TODO work:
    // 1. - create key for "get_tree_element()"" with seed -- we need different seeds!
    //   a)
    //      call lms::mod.rs::generate_key_pair() ? I think except the seed, all parameters for key-gen are irrelevant
    //         hss::reference_impl_private_key.rs : SeedAndLmsTreeIdentifier<H>,
    //         hss::parameter.rs::HssParameter<H>,
    //         used_leafs_index: &u32,
    //         aux_data: &mut Option<MutableExpandedAuxData>,*/
    let mut seed_and_lms_tree_identifier = SeedAndLmsTreeIdentifier::<Sha256_256>::default();
    //OsRng.fill_bytes(seed_and_lms_tree_identifier.seed.as_mut_slice());

    //   b) lms::definitions.rs::LmsPrivateKey::new()
    // let mut private_key = LmsPrivateKey::new(
    //    seed_and_lms_tree_identifier.seed.clone(),
    //    seed_and_lms_tree_identifier.lms_tree_identifier,
    //    0,
    //    LmotsAlgorithm::construct_default_parameter(),
    //    LmsAlgorithm::construct_default_parameter(),
    //);
    // 2. - call get_tree_element(idx, LmsPrivateKey, None)

    Ok(node_value)
}

/// Parameters:
///   other_hss_pub_keys: HSS public keys of other signing entities
///   own_hss_pub_key:    HSS public key of the calling signing entity (separate, to create entity's individual authentication path).
/// Returns the root node (public key) which comprises the authentication path -- whihch is different for every signing entity!
pub fn gen_sst_pubkey() -> Result<(), Error> {

    // that's different now, because we do not generate a whole LMS based on
    // one seed but on different intermediate nodes (with different seeds).
    // -> Check whether there is a function that takes intermediate nodes! (e.g. function using aux data)
    //    because that's basically what we need

    // @TODO: use the Error
    Ok(())
}
