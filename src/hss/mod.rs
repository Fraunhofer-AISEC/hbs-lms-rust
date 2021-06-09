use crate::util::ustr::str32u;

pub fn hss_verify(message: &[u8], signature: &[u8], public_key: &[u8]) -> bool {
    // Todo: Check if HSS Levels = 1 and then forward data;

    assert!(public_key.len() > 4);
    let hss_levels = str32u(&public_key[0..4]);

    assert!(hss_levels == 1);

    assert!(signature.len() > 4);
    let hss_levels = str32u(&signature[0..4]);

    assert!(hss_levels == 0);

    crate::lms::verify(message, &signature[4..], &public_key[4..])
}
