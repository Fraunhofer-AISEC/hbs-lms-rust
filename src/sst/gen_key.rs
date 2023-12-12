//use crate::{signature::Error, HssParameter, Sha256_256};
use crate::signature::Error;

pub fn gen_hss_key() -> Result<(), Error> {
    // @TODO: nyi
    Ok(())
}
/// Parameters:
///   other_hss_pub_keys: HSS public keys of other signing entities
///   own_hss_pub_key:    HSS public key of the calling signing entity (separate, to create entity's individual authentication path).
/// Returns the root node (public key) which comprises the authentication path -- whihch is different for every signing entity!

pub fn gen_sst_pubkey() -> Result<(), Error> {

    // @TODO: use the Error
    Ok(())
}
