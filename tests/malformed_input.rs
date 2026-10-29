//! Malformed signatures, public keys and aux data must be rejected or ignored, never cause a panic.
//!
//! All keys are test keys from a fixed seed, with LMS_SHA256_M32_H5 and LMOTS_SHA256_N32_W8.

use hbs_lms::signature::SignerMut;
use hbs_lms::{
    keygen, verify, HssParameter, LmotsAlgorithm, LmsAlgorithm, Seed, Sha256_256, SigningKey,
    VerifyingKey,
};

type H = Sha256_256;

const MESSAGE: &[u8] = b"message";

// Sizes in bytes for LMS_SHA256_M32_H5 with LMOTS_SHA256_N32_W8 (RFC 8554, sections 4 and 5).
const LMOTS_SIGNATURE_LEN: usize = 4 + 32 + 34 * 32; // type, C, y[0..34]
const LMS_SIGNATURE_LEN: usize = 4 + LMOTS_SIGNATURE_LEN + 4 + 5 * 32; // q, LM-OTS signature, type, path
const LMS_PUBLIC_KEY_LEN: usize = 4 + 4 + 16 + 32; // LMS type, LM-OTS type, I, T[1]
const SIGNED_PUBLIC_KEY_LEN: usize = LMS_SIGNATURE_LEN + LMS_PUBLIC_KEY_LEN;

fn key_pair(levels: usize, aux_data: Option<&mut &mut [u8]>) -> (SigningKey<H>, VerifyingKey<H>) {
    let parameters = vec![HssParameter::new(LmotsAlgorithm::LmotsW8, LmsAlgorithm::LmsH5); levels];
    keygen::<H>(&parameters, &Seed::from([0x5a; 32]), aux_data).expect("key generation")
}

fn sign(signing_key: &mut SigningKey<H>) -> Vec<u8> {
    signing_key
        .try_sign(MESSAGE)
        .expect("signing")
        .as_ref()
        .to_vec()
}

#[test]
fn truncated_signatures_are_rejected() {
    for levels in [1, 2] {
        let (mut signing_key, verifying_key) = key_pair(levels, None);
        let public_key = verifying_key.as_slice();
        let signature = sign(&mut signing_key);
        assert!(verify::<H>(MESSAGE, &signature, public_key).is_ok());

        for len in 0..signature.len() {
            assert!(
                verify::<H>(MESSAGE, &signature[..len], public_key).is_err(),
                "{} level(s), signature cut to {} bytes",
                levels,
                len
            );
        }
    }
}

#[test]
fn truncated_public_keys_are_rejected() {
    let (mut signing_key, verifying_key) = key_pair(1, None);
    let public_key = verifying_key.as_slice();
    let signature = sign(&mut signing_key);
    assert!(verify::<H>(MESSAGE, &signature, public_key).is_ok());

    for len in 0..public_key.len() {
        assert!(
            verify::<H>(MESSAGE, &signature, &public_key[..len]).is_err(),
            "public key cut to {} bytes",
            len
        );
    }
}

#[test]
fn unknown_type_codes_are_rejected() {
    let (mut signing_key, verifying_key) = key_pair(1, None);
    let public_key = verifying_key.as_slice().to_vec();
    let signature = sign(&mut signing_key);
    assert!(verify::<H>(MESSAGE, &signature, &public_key).is_ok());

    // Signature: Nspk (4), q (4), LM-OTS signature starting with its type, LMS type, path.
    let signature_type_offsets = [8, 8 + LMOTS_SIGNATURE_LEN];
    // Public key: L (4), LMS type (4), LM-OTS type (4), I, T[1].
    let public_key_type_offsets = [4, 8];

    for type_code in [0, 0x99, u32::MAX] {
        for offset in signature_type_offsets {
            let mut bad_signature = signature.clone();
            bad_signature[offset..offset + 4].copy_from_slice(&type_code.to_be_bytes());
            assert!(
                verify::<H>(MESSAGE, &bad_signature, &public_key).is_err(),
                "type code {:#x} at signature offset {}",
                type_code,
                offset
            );
        }
        for offset in public_key_type_offsets {
            let mut bad_public_key = public_key.clone();
            bad_public_key[offset..offset + 4].copy_from_slice(&type_code.to_be_bytes());
            assert!(
                verify::<H>(MESSAGE, &signature, &bad_public_key).is_err(),
                "type code {:#x} at public key offset {}",
                type_code,
                offset
            );
        }
    }
}

#[test]
fn too_many_hss_levels_are_rejected() {
    let (mut signing_key, verifying_key) = key_pair(2, None);
    let public_key = verifying_key.as_slice();
    let signature = sign(&mut signing_key);
    assert!(verify::<H>(MESSAGE, &signature, public_key).is_ok());
    assert_eq!(
        signature.len(),
        4 + SIGNED_PUBLIC_KEY_LEN + LMS_SIGNATURE_LEN
    );

    // Nspk (4), one signed public key, the last LMS signature.
    let signed_public_key = &signature[4..4 + SIGNED_PUBLIC_KEY_LEN];
    let last_signature = &signature[4 + SIGNED_PUBLIC_KEY_LEN..];

    for nspk in [8, u32::MAX] {
        let mut bad_signature = nspk.to_be_bytes().to_vec();
        for _ in 0..8 {
            bad_signature.extend_from_slice(signed_public_key);
        }
        bad_signature.extend_from_slice(last_signature);
        assert!(
            verify::<H>(MESSAGE, &bad_signature, public_key).is_err(),
            "Nspk {:#x} with 8 signed public keys",
            nspk
        );
    }
}

#[test]
fn damaged_aux_data_is_ignored() {
    let mut aux_data = vec![0u8; 4096];
    let mut aux_slice: &mut [u8] = &mut aux_data;
    let (signing_key, verifying_key) = key_pair(1, Some(&mut aux_slice));
    // Key generation shrinks the slice to the aux data it wrote.
    let aux_len = aux_slice.len();
    aux_data.truncate(aux_len);
    let public_key = verifying_key.as_slice();

    // Signing is deterministic: every case must give the signature made without aux data.
    let reference_signature = sign(&mut signing_key.clone());

    let mut flipped_levels = aux_data.clone();
    flipped_levels[3] ^= 0xff;

    let mut cases = vec![
        (String::from("intact aux data"), aux_data.clone()),
        (
            String::from("aux data with flipped level bits"),
            flipped_levels,
        ),
    ];
    for len in [aux_len - 1, aux_len / 2, 5, 4, 3, 1] {
        cases.push((
            format!("aux data cut to {} bytes", len),
            aux_data[..len].to_vec(),
        ));
    }

    for (case, mut aux) in cases {
        let mut signing_key = signing_key.clone();
        let mut aux_slice: &mut [u8] = &mut aux;
        let signature = signing_key
            .try_sign_with_aux(MESSAGE, Some(&mut aux_slice))
            .unwrap_or_else(|_| panic!("signing failed with {}", case));
        assert!(
            verify::<H>(MESSAGE, signature.as_ref(), public_key).is_ok(),
            "signature made with {} does not verify",
            case
        );
        assert_eq!(
            signature.as_ref(),
            &reference_signature[..],
            "signature made with {} differs from the one made without aux data",
            case
        );
    }
}

#[test]
fn empty_aux_buffer_is_ignored() {
    let mut empty: &mut [u8] = &mut [];
    let (mut signing_key, verifying_key) = key_pair(1, Some(&mut empty));
    assert_eq!(verifying_key, key_pair(1, None).1);

    let mut empty: &mut [u8] = &mut [];
    let signature = signing_key
        .try_sign_with_aux(MESSAGE, Some(&mut empty))
        .expect("signing with an empty aux buffer");
    assert!(verify::<H>(MESSAGE, signature.as_ref(), verifying_key.as_slice()).is_ok());
}
