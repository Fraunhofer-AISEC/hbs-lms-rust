use crate::signature::Error;
use crate::{
    constants::{MAX_HASH_SIZE, MAX_SSTS_SIGNING_ENTITIES, ILEN},
    hasher::HashChain,
    hss::{
        aux::{hss_finalize_aux_data, hss_is_aux_data_used},
        definitions::HssPrivateKey,
        definitions::HssPublicKey,
        reference_impl_private_key::{ReferenceImplPrivateKey, Seed},
        SigningKey, VerifyingKey,
    },
    lms::definitions::LmsPrivateKey,
    lms::helper::get_tree_element,
    sst::{
        helper, helper::get_subtree_node_idx, parameters::SstExtension, parameters::SstsParameter,
    },
};

use tinyvec::ArrayVec;

pub fn prepare_sst_keygen<H: HashChain>(
    sst_param: &SstsParameter<H>,
    seed: &Seed<H>,
    aux_data: Option<&mut &mut [u8]>,
    tree_identifier: &mut [u8; ILEN],
) -> Result<(SigningKey<H>, ArrayVec<[u8; MAX_HASH_SIZE]>), Error> {
    if sst_param.get_signing_entity_idx() == 0 || sst_param.get_top_div_height() == 0 {
        return Err(Error::new());
    }

    // create two representations of private keys because we need their data elements
    // -> ReferenceImplPrivateKey and SigningKey
    let rfc_private_key =
        ReferenceImplPrivateKey::generate(sst_param, seed).map_err(|_| Error::new())?;
    let signing_key = SigningKey::from_bytes(&rfc_private_key.to_binary_representation())?;

    // get expanded AUX data
    let is_aux_data_used = if let Some(ref aux_data) = aux_data {
        hss_is_aux_data_used(aux_data)
    } else {
        false
    };

    let mut expanded_aux_data = HssPrivateKey::get_expanded_aux_data(
        aux_data,
        &rfc_private_key,
        sst_param.get_hss_parameters()[0].get_lms_parameter(),
        is_aux_data_used,
    );

    // calculate our intermediate node hash value; for this we have to generate a LmsPrivateKey

    // TODO/Review: better option? redundant (used leafs calculation)
    let used_leafs_index = helper::get_sst_first_leaf_idx(
        sst_param.get_signing_entity_idx(),
        sst_param.get_hss_parameters()[0]
            .get_lms_parameter()
            .get_tree_height(),
        sst_param.get_top_div_height());

    let mut seed_and_lms_tree_ident = rfc_private_key.generate_root_seed_and_lms_tree_identifier();

    if tree_identifier.iter().all(|&byte| byte == 0) {
        tree_identifier.clone_from_slice(&seed_and_lms_tree_ident.lms_tree_identifier);
    } else {
        seed_and_lms_tree_ident.lms_tree_identifier.clone_from_slice(tree_identifier);
    }

    let sst_ext = SstExtension {
        signing_entity_idx: rfc_private_key.sst_ext.signing_entity_idx,
        top_div_height: rfc_private_key.sst_ext.top_div_height,
    };

    let sst_ext_option = Some(sst_ext);

    let our_node_index = get_subtree_node_idx(
        sst_param.get_signing_entity_idx(),
        sst_param.get_hss_parameters()[0]
            .get_lms_parameter()
            .get_tree_height(),
        sst_param.get_top_div_height(),
    );

    let lms_private_key = LmsPrivateKey::<H>::new(
        seed_and_lms_tree_ident.seed.clone(),
        seed_and_lms_tree_ident.lms_tree_identifier,
        used_leafs_index, // actually not used in "get_tree_element", irrelevant
        *sst_param.get_hss_parameters()[0].get_lmots_parameter(),
        *sst_param.get_hss_parameters()[0].get_lms_parameter(),
        sst_ext_option,
    );

    let our_intermed_node_value = get_tree_element(
        our_node_index as usize,
        &lms_private_key,
        &mut expanded_aux_data,
    );
    if let Some(expanded_aux_data) = expanded_aux_data.as_mut() {
        hss_finalize_aux_data::<H>(expanded_aux_data, rfc_private_key.seed.as_slice());
    }

    Ok((signing_key, our_intermed_node_value))
}

pub fn get_num_signing_entities<H: HashChain>(private_key: &[u8]) -> Result<u32, Error> {
    let rfc_private_key = ReferenceImplPrivateKey::<H>::from_binary_representation(private_key)
        .map_err(|_| Error::new())?;

    let num_signing_entities = 2u32.pow(rfc_private_key.sst_ext.top_div_height as u32);

    Ok(num_signing_entities)
}

pub fn finalize_sst_keygen<H: HashChain>(
    private_key: &[u8],
    interm_nodes: &ArrayVec<[ArrayVec<[u8; MAX_HASH_SIZE]>; MAX_SSTS_SIGNING_ENTITIES]>,
    aux_data: Option<&mut &mut [u8]>,
    tree_identifier: &[u8; ILEN],
) -> Result<VerifyingKey<H>, Error> {
    let rfc_private_key = ReferenceImplPrivateKey::<H>::from_binary_representation(private_key)
        .map_err(|_| Error::new())?;

    let hss_public_key =
        HssPublicKey::from_with_sst(&rfc_private_key, aux_data, interm_nodes, tree_identifier)
            .map_err(|_| Error::new())?;

    let verifying_key = VerifyingKey::<H>::from_bytes(&hss_public_key.to_binary_representation())?;

    Ok(verifying_key)
}
