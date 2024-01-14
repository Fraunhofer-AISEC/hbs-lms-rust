use crate::constants::LmsTreeIdentifier;
use crate::signature::Error;
use crate::{
    constants::{D_INTR, MAX_DSM_SIGNING_ENTITIES, MAX_HASH_SIZE},
    hasher::HashChain,
    hss::{
        definitions::HssPublicKey,
        reference_impl_private_key::{ReferenceImplPrivateKey, Seed},
        SigningKey,
    },
    lms::definitions::LmsPrivateKey,
    lms::helper::get_tree_element,
    sst::{
        helper, helper::get_subtree_node_idx, parameters::SstExtension, parameters::SstsParameter,
    },
};

use tinyvec::ArrayVec;

pub fn gen_sst_subtree<H: HashChain>(
    sst_param: &SstsParameter<H>,
    seed: &Seed<H>,
) -> Result<(SigningKey<H>, ArrayVec<[u8; MAX_HASH_SIZE]>), Error> {
    println!("gen_sst_subtree");

    // private keys
    let private_key =
        ReferenceImplPrivateKey::generate(sst_param, seed).map_err(|_| Error::new())?;
    let signing_key = SigningKey::from_bytes(&private_key.to_binary_representation())?;

    // TODO review: redundant...used leafs calculation
    let mut used_leafs_index = 0;
    if sst_param.get_top_height() != 0 {
        // TODO: is there a better (Rust-idiomatic) approach?
        used_leafs_index = helper::get_sst_first_leaf_idx(
            sst_param.get_entity_idx(),
            sst_param.get_hss_parameters()[0]
                .get_lms_parameter()
                .get_tree_height(),
            sst_param.get_top_height(),
        );
    }

    // our intermediate node value
    // TODO: review! not elegant to create an LmsPrivateKey and SeedAndLmsTreeIdentifier

    let seed_and_lms_tree_ident = private_key.generate_root_seed_and_lms_tree_identifier();

    let sst_ext = SstExtension {
        signing_instance: private_key.sst_ext.signing_instance,
        top_tree_height: private_key.sst_ext.top_tree_height,
    };

    let mut sst_ext_option = None;
    let mut our_node_index = 0;

    if private_key.sst_ext.signing_instance != 0 {
        sst_ext_option = Some(sst_ext);

        our_node_index = get_subtree_node_idx(
            sst_param.get_entity_idx(),
            sst_param.get_hss_parameters()[0]
                .get_lms_parameter()
                .get_tree_height(),
            sst_param.get_top_height(),
        );
    }

    let lms_private_key = LmsPrivateKey::<H>::new(
        seed_and_lms_tree_ident.seed.clone(),
        seed_and_lms_tree_ident.lms_tree_identifier,
        used_leafs_index as u32, // actually not used in "get_tree_element", irrelevant
        *sst_param.get_hss_parameters()[0].get_lmots_parameter(),
        *sst_param.get_hss_parameters()[0].get_lms_parameter(),
        sst_ext_option,
    );

    let our_node_value = get_tree_element(our_node_index as usize, &lms_private_key, &mut None);

    Ok((signing_key, our_node_value))
}

/// Parameters:
///   other_hss_pub_keys: HSS public keys of other signing entities
///   own_hss_pub_key:    HSS public key of the calling signing entity (separate, to create entity's individual authentication path).
/// Returns the root node (public key) which comprises the authentication path -- whihch is different for every signing entity!
/*
pub fn gen_sst_pubkey() -> Result<(), Error> {

    // that's different now, because we do not generate a whole LMS based on
    //   one seed but on different intermediate nodes (with different seeds).
    // -> Check whether there is a function that takes intermediate nodes! (e.g. function using aux data)
    //    because that's basically what we need

    // @TODO: use the Error
    Ok(())
}
*/

pub fn get_config<H: HashChain>(
    private_key: &[u8],
) -> Result<(SstsParameter<H>, LmsTreeIdentifier), Error> {
    let rfc_private_key = ReferenceImplPrivateKey::<H>::from_binary_representation(private_key)
        .map_err(|_| Error::new())?;

    let hss_pubkey = HssPublicKey::from(&rfc_private_key, None).map_err(|_| Error::new())?;
    let lms_tree_ident = hss_pubkey.public_key.lms_tree_identifier;

    let hss_param_vec = rfc_private_key
        .compressed_parameter
        .to()
        .map_err(|_| Error::new())?;

    let ssts_param = SstsParameter::new(
        hss_param_vec,
        rfc_private_key.sst_ext.top_tree_height,
        rfc_private_key.sst_ext.signing_instance,
    );

    Ok((ssts_param, lms_tree_ident))
}

pub fn gen_pub_key<H: HashChain>(
    av_of_nodes: &ArrayVec<[ArrayVec<[u8; MAX_HASH_SIZE]>; MAX_DSM_SIGNING_ENTITIES]>,
    top_tree_height: u8,
    lms_tree_ident: LmsTreeIdentifier,
) -> Result<ArrayVec<[u8; MAX_HASH_SIZE]>, Error> {
    let pubkey = get_node_hash_val::<H>(1, av_of_nodes, top_tree_height, lms_tree_ident);

    Ok(pubkey)
}

fn get_node_hash_val<H: HashChain>(
    index: u32,
    av_of_nodes: &ArrayVec<[ArrayVec<[u8; MAX_HASH_SIZE]>; MAX_DSM_SIGNING_ENTITIES]>,
    top_tree_height: u8,
    lms_tree_ident: LmsTreeIdentifier,
) -> ArrayVec<[u8; MAX_HASH_SIZE]> {
    let index_level =
        (core::mem::size_of_val(&index) * 8 - index.leading_zeros() as usize - 1) as u8;

    let hasher = H::default()
        .chain(lms_tree_ident)
        .chain((index as u32).to_be_bytes());

    // if index is at lowest level (where we have the signing entity node hash values)
    let result = if index_level == top_tree_height {
        // return the node value from array of intermedediate node hash values
        /* access vector elements via "leaf numbers" = 0..signing_entites-1 */
        let leaf_number = (index as usize) - 2usize.pow(top_tree_height as u32);
        av_of_nodes[leaf_number]
    } else {
        // we are "above" the intermediate node hash values -> go down
        let left = get_node_hash_val::<H>(index * 2, av_of_nodes, top_tree_height, lms_tree_ident);
        let right =
            get_node_hash_val::<H>(index * 2 + 1, av_of_nodes, top_tree_height, lms_tree_ident);

        hasher
            .chain(D_INTR)
            .chain(left.as_slice())
            .chain(right.as_slice())
            .finalize()
    };

    return result;
}

pub fn gen_sst_pubkey<H: HashChain>(_private_key: &[u8], _aux_data: Option<&mut &mut [u8]>)
//-> Result<(VerifyingKey<H>), Error>
{

    // public keys -> gen_sst_pubkey
    // check how the &[u8] is transformed to RefPrivKey in sign()
    // let hss_public_key = HssPublicKey::from(&private_key, aux_data).map_err(|_| Error::new())?;
    //let verifying_key = VerifyingKey::from_bytes(&hss_public_key.to_binary_representation())?;

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

    // @TODO work:
    // 1. - create key for "get_tree_element()"" with seed -- we need different seeds!
    //   a)
    //      call lms::mod.rs::generate_key_pair() ? I think except the seed, all parameters for key-gen are irrelevant
    //         hss::reference_impl_private_key.rs : SeedAndLmsTreeIdentifier<H>,
    //         hss::parameter.rs::HssParameter<H>,
    //         used_leafs_index: &u32,
    //         aux_data: &mut Option<MutableExpandedAuxData>,
    // let _seed_and_lms_tree_identifier = SeedAndLmsTreeIdentifier::<Sha256_256>::default();
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

    //Ok(verifying_key)
}
