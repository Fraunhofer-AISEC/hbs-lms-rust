use crate::signature::Error;
use crate::{
    constants::{LmsTreeIdentifier, Node, MAX_HASH_SIZE, MAX_SSTS_SIGNING_ENTITIES},
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
    sst::{helper::get_sst_root_node_idx, parameters::SstExtension},
    HssParameter,
};

use tinyvec::ArrayVec;

pub fn prepare_sst_keygen<H: HashChain>(
    hss_parameters: &[HssParameter<H>],
    sst_extension: &SstExtension,
    seed: &Seed<H>,
    aux_data: Option<&mut &mut [u8]>,
    tree_identifier: &mut LmsTreeIdentifier,
) -> Result<(SigningKey<H>, Node), Error> {
    let rfc_private_key =
        ReferenceImplPrivateKey::generate(hss_parameters, seed, Some(sst_extension.clone()))
            .map_err(|_| Error::new())?;

    let is_aux_data_used = aux_data.as_ref().map_or(false, |d| hss_is_aux_data_used(d));

    let mut expanded_aux_data = HssPrivateKey::get_expanded_aux_data(
        aux_data,
        &rfc_private_key,
        hss_parameters[0].get_lms_parameter(),
        is_aux_data_used,
    );

    // Harmonising LMS tree identifier of root tree
    let mut seed_and_lms_tree_ident = rfc_private_key.generate_root_seed_and_lms_tree_identifier();
    if tree_identifier.iter().all(|&byte| byte == 0) {
        tree_identifier.clone_from_slice(&seed_and_lms_tree_ident.lms_tree_identifier);
    } else {
        seed_and_lms_tree_ident
            .lms_tree_identifier
            .clone_from_slice(tree_identifier);
    }

    let our_node_index =
        get_sst_root_node_idx(hss_parameters[0].get_lms_parameter(), sst_extension);

    let lms_private_key = LmsPrivateKey::<H>::new(
        seed_and_lms_tree_ident.seed.clone(),
        seed_and_lms_tree_ident.lms_tree_identifier,
        rfc_private_key
            .compressed_used_leafs_indexes
            .to(hss_parameters)[0],
        *hss_parameters[0].get_lmots_parameter(),
        *hss_parameters[0].get_lms_parameter(),
        Some(sst_extension.clone()),
    );

    let our_intermed_node_value = get_tree_element(
        our_node_index as usize,
        &lms_private_key,
        &mut expanded_aux_data,
    );

    hss_finalize_aux_data::<H>(
        expanded_aux_data.as_mut().ok_or(Error::new())?,
        rfc_private_key.seed.as_slice(),
    );

    let signing_key = SigningKey::from_bytes(&rfc_private_key.to_binary_representation())?;
    Ok((signing_key, our_intermed_node_value))
}

pub fn finalize_sst_keygen<H: HashChain>(
    private_key: &[u8],
    interm_nodes: &ArrayVec<[ArrayVec<[u8; MAX_HASH_SIZE]>; MAX_SSTS_SIGNING_ENTITIES]>,
    aux_data: Option<&mut &mut [u8]>,
    tree_identifier: &LmsTreeIdentifier,
) -> Result<VerifyingKey<H>, Error> {
    let rfc_private_key = ReferenceImplPrivateKey::<H>::from_binary_representation(private_key)
        .map_err(|_| Error::new())?;

    let hss_public_key =
        HssPublicKey::from_with_sst(&rfc_private_key, aux_data, interm_nodes, tree_identifier)
            .map_err(|_| Error::new())?;

    VerifyingKey::<H>::from_bytes(&hss_public_key.to_binary_representation())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::util::helper::test_helper::gen_random_seed;
    use crate::HssParameter;
    use crate::Sha256_128;
    use crate::Sha256_192;
    use crate::Sha256_256;
    use signature::Verifier;

    #[test]
    fn test_prepare_sst_keygen_se_without_lms_tree_id() {
        const SIGNING_ENTITY_IDX: u32 = 3;
        const L0_TOP_DIV: u32 = 4;

        let mut lms_tree_identifier = LmsTreeIdentifier::default();
        let seed = gen_random_seed::<Sha256_128>();
        let hss_parameters = [
            HssParameter::construct_default_parameters(),
            HssParameter::construct_default_parameters(),
        ];
        let sst_extension = SstExtension::new(SIGNING_ENTITY_IDX as u8, L0_TOP_DIV as u8).unwrap();
        let mut aux_data = [0u8; 4 + MAX_HASH_SIZE + 2usize.pow(L0_TOP_DIV) * MAX_HASH_SIZE];
        let aux_ref: &mut &mut [u8] = &mut &mut aux_data[..];
        let aux_option = Some(aux_ref);

        let (_signing_key, interm_node) = prepare_sst_keygen::<Sha256_128>(
            &hss_parameters,
            &sst_extension,
            &seed,
            aux_option,
            &mut lms_tree_identifier,
        )
        .unwrap();
        assert_ne!(lms_tree_identifier, LmsTreeIdentifier::default());
        assert_eq!(
            interm_node.as_slice().len(),
            LmsTreeIdentifier::default().len()
        );
        assert_ne!(interm_node.as_slice(), &LmsTreeIdentifier::default());
    }

    #[test]
    fn test_prepare_sst_keygen_se_with_lms_tree_id() {
        const SIGNING_ENTITY_IDX: u32 = 3;
        const L0_TOP_DIV: u32 = 4;

        let mut lms_tree_identifier = LmsTreeIdentifier::default();
        lms_tree_identifier[0] = 0xaa;
        let copy_lms_tree_identifier = lms_tree_identifier;
        let seed = gen_random_seed::<Sha256_128>();
        let hss_parameters = [
            HssParameter::construct_default_parameters(),
            HssParameter::construct_default_parameters(),
        ];
        let sst_extension = SstExtension::new(SIGNING_ENTITY_IDX as u8, L0_TOP_DIV as u8).unwrap();
        let mut aux_data = [0u8; 4 + MAX_HASH_SIZE + 2usize.pow(L0_TOP_DIV) * MAX_HASH_SIZE];
        let aux_ref: &mut &mut [u8] = &mut &mut aux_data[..];
        let aux_option = Some(aux_ref);

        let _ = prepare_sst_keygen::<Sha256_128>(
            &hss_parameters,
            &sst_extension,
            &seed,
            aux_option,
            &mut lms_tree_identifier,
        )
        .unwrap();
        assert_eq!(lms_tree_identifier, copy_lms_tree_identifier);
    }

    #[test]
    fn signing_sst_sha256_128() {
        signing_sst_core::<Sha256_128>();
    }

    #[test]
    fn signing_sst_sha256_192() {
        signing_sst_core::<Sha256_192>();
    }

    #[test]
    fn signing_sst_sha256_256() {
        signing_sst_core::<Sha256_256>();
    }

    fn signing_sst_core<H: HashChain>() {
        const SIGNING_ENTITY_IDX: u32 = 3;
        const L0_TOP_DIV: u32 = 4;

        let mut message = [
            32u8, 48, 2, 1, 48, 58, 20, 57, 9, 83, 99, 255, 0, 34, 2, 1, 0,
        ];

        let mut lms_tree_identifier = LmsTreeIdentifier::default();
        let seed = gen_random_seed::<H>();
        let hss_parameters = [
            HssParameter::construct_default_parameters(),
            HssParameter::construct_default_parameters(),
        ];
        let sst_extension = SstExtension::new(SIGNING_ENTITY_IDX as u8, L0_TOP_DIV as u8).unwrap();
        let mut aux_data = [0u8; 4 + MAX_HASH_SIZE + 2usize.pow(L0_TOP_DIV) * MAX_HASH_SIZE];
        let aux_ref: &mut &mut [u8] = &mut &mut aux_data[..];
        let mut aux_option = Some(aux_ref);

        let (mut signing_key, interm_node) = prepare_sst_keygen::<H>(
            &hss_parameters,
            &sst_extension,
            &seed,
            Some(aux_option.as_mut().unwrap()),
            &mut lms_tree_identifier,
        )
        .unwrap();

        let mut interm_nodes = ArrayVec::<[Node; MAX_SSTS_SIGNING_ENTITIES]>::new();
        let mut tmp_node = Node::new();
        tmp_node.extend_from_slice(&interm_node);
        for _ in 0..2usize.pow(L0_TOP_DIV) {
            interm_nodes.push(tmp_node);
        }

        let verifying_key = finalize_sst_keygen::<H>(
            signing_key.as_slice(),
            &interm_nodes,
            Some(aux_option.as_mut().unwrap()),
            &lms_tree_identifier,
        )
        .unwrap();

        let signature = signing_key
            .try_sign_with_aux(&message, aux_option, Some(&lms_tree_identifier))
            .unwrap();

        assert!(verifying_key.verify(&message, &signature).is_ok());
        message[0] = 33;
        assert!(verifying_key.verify(&message, &signature).is_err());
    }
}
