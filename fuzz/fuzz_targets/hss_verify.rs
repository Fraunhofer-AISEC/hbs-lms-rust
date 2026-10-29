#![no_main]

use hbs_lms::Sha256_256;
use libfuzzer_sys::fuzz_target;

// Input: one byte with the public key length, then the public key, then the signature.
// Verifying any input must return Ok or Err; a panic is a bug.
fuzz_target!(|data: &[u8]| {
    if let Some((&public_key_len, rest)) = data.split_first() {
        let (public_key, signature) = rest.split_at(usize::from(public_key_len).min(rest.len()));
        let _ = hbs_lms::verify::<Sha256_256>(b"message", signature, public_key);
    }
});
