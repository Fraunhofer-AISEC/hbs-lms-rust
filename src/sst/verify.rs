use crate::HashChain;
//use crate::hss;

pub fn verify<H: HashChain>(_message: &[u8], _signature: &[u8], _public_key: &[u8]) -> bool {
    // @TODO nyi
    // - verify SST (= HSS/LMS) signature (same as for HSS/LMS)

    //let _hss_sig = hss::hss_verify::<H>(&message, &signature, &public_key).is_ok();

    // - verify ST: calc. ST key candidate (using SST pubkey and authentication path), compare with stored ST publey

    true
}
