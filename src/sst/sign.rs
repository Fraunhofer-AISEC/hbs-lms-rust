use crate::signature::Error;
use crate::constants::Node;
use crate::hss::signing::HssSignature;
use crate::HashChain;
use tinyvec::ArrayVec;

pub struct SstsSignature<H: HashChain> {
    pub hss_signature: HssSignature<H>,
    // use an ArrayVec with a @TODO max size?
    pub our_node: Node,
    pub auth_path: ArrayVec<[Node; 32]>, // order: sort on-the-fly dep. on Node's values?
}

pub fn sign<H: HashChain>(
    _message: &[u8],
) -> Result<(), Error> {
    // nyi
    /* hbs_lms::sign::<Hasher>(
        &message_data,
        &private_key_data,
        &mut private_key_update_function,
        Some(aux_slice),
    ) */
    Ok(())
}
