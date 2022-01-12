use rand::{rngs::OsRng, RngCore};
use std::{
    io::{Read, Write},
    path::{Path, PathBuf},
    process::Command,
};

use hbs_lms::{HssParameter, LmotsAlgorithm, LmsAlgorithm, Seed, Sha256};
use tempfile::TempDir;

const MESSAGE_FILE_NAME: &str = "message.txt";
const SIGNATURE_FILE_NAME: &str = "message.txt.sig";

const KEY_NAME: &str = "testkey";
const PUBLIC_KEY_NAME: &str = "testkey.pub";
const PRIVATE_KEY_NAME: &str = "testkey.prv";
const AUX_DATA_NAME: &str = "testkey.aux";

const PARAMETER: &str = "5/1,5/1:2000";

const TEST_SEED: [u8; 32] = [
    23, 54, 12, 64, 2, 5, 77, 23, 188, 31, 34, 46, 88, 99, 21, 22, 23, 54, 12, 64, 2, 5, 77, 23,
    188, 31, 34, 46, 88, 99, 21, 22,
];

#[test]
#[ignore]
fn create_signature_with_reference_implementation() {
    let tempdir = tempfile::tempdir().unwrap();

    reference_genkey(&tempdir);
    create_message_file(&tempdir);

    reference_sign(&tempdir);
    own_verify(&tempdir);

    // Sign it twice to test that private key gets advanced

    reference_sign(&tempdir);
    own_verify(&tempdir);
}

#[test]
#[ignore]
fn create_signature_with_own_implementation() {
    let tempdir = tempfile::tempdir().unwrap();
    let path = tempdir.path();

    let mut aux_data = vec![0u8; 2000];
    let aux_slice = &mut &mut aux_data[..];

    let mut seed = Seed::default();
    OsRng.fill_bytes(&mut seed);
    let (mut signing_key, verifying_key) = hbs_lms::keygen::<Sha256>(
        &[
            HssParameter::construct_default_parameters(),
            HssParameter::construct_default_parameters(),
        ],
        &seed,
        Some(aux_slice),
    )
    .expect("Should create HSS keys");

    save_file(
        path.join(PUBLIC_KEY_NAME).to_str().unwrap(),
        verifying_key.as_slice(),
    );

    create_message_file(&tempdir);
    let mut message_data = read_message(path);

    own_signing(
        &tempdir,
        &mut message_data,
        signing_key.as_mut_slice(),
        aux_slice,
    );

    reference_verify(&tempdir);

    own_signing(
        &tempdir,
        &mut message_data,
        signing_key.as_mut_slice(),
        aux_slice,
    );

    reference_verify(&tempdir);
}

#[test]
#[ignore]
fn test_private_key_format() {
    let tempdir = tempfile::tempdir().unwrap();
    let path = tempdir.path();

    reference_genkey(&tempdir);
    create_message_file(&tempdir);

    let mut private_key = read_private_key(path);
    let mut message_data = read_message(path);
    let mut aux_data = read_aux_data(path);

    own_signing(&tempdir, &mut message_data, &mut private_key, &mut aux_data);
    reference_verify(&tempdir);

    reference_sign(&tempdir);
    own_verify(&tempdir);
}

#[test]
#[ignore]
fn should_produce_same_private_key() {
    let tempdir = tempfile::tempdir().unwrap();
    let path = tempdir.path();

    reference_genkey_seed(&tempdir, &TEST_SEED);

    let parameters = HssParameter::<Sha256>::new(LmotsAlgorithm::LmotsW1, LmsAlgorithm::LmsH5);

    let (sk, vk) = hbs_lms::keygen(&[parameters, parameters], &TEST_SEED, None).unwrap();

    let ref_signing_key = read_private_key(path);
    let ref_verifying_key = read_public_key(path);

    assert!(ref_signing_key == sk.as_slice());
    assert!(ref_verifying_key == vk.as_slice());
}

fn read_private_key(path: &Path) -> Vec<u8> {
    read_file(path.join(PRIVATE_KEY_NAME).to_str().unwrap())
}

fn read_aux_data(path: &Path) -> Vec<u8> {
    read_file(path.join(AUX_DATA_NAME).to_str().unwrap())
}

fn read_message(path: &Path) -> Vec<u8> {
    read_file(path.join(MESSAGE_FILE_NAME).to_str().unwrap())
}

fn read_public_key(path: &Path) -> Vec<u8> {
    read_file(path.join(PUBLIC_KEY_NAME).to_str().unwrap())
}

fn save_file(file_name: &str, data: &[u8]) {
    let mut file = std::fs::File::create(file_name)
        .unwrap_or_else(|_| panic!("Could not open file: {}", file_name));
    file.write_all(data).expect("Could not write file.");
}

fn read_file(file_name: &str) -> Vec<u8> {
    let mut file = std::fs::File::open(file_name)
        .unwrap_or_else(|_| panic!("Could not read data from: {}", file_name));

    let mut data: Vec<u8> = Vec::new();
    file.read_to_end(&mut data)
        .unwrap_or_else(|_| panic!("Could not read data from: {}", file_name));

    data
}

fn own_signing(
    temp_path: &TempDir,
    message_data: &mut [u8],
    private_key: &mut [u8],
    mut aux_data: &mut [u8],
) {
    let aux_slice: &mut &mut [u8] = &mut aux_data;

    let private_key_before = private_key.to_vec();

    let mut update_private_key = |new_key: &[u8]| {
        private_key.copy_from_slice(new_key);
        Ok(())
    };

    let result = hbs_lms::sign::<Sha256>(
        message_data,
        &private_key_before,
        &mut update_private_key,
        Some(aux_slice),
    )
    .expect("Signing should succed.");
    save_file(
        temp_path.path().join(SIGNATURE_FILE_NAME).to_str().unwrap(),
        result.as_ref(),
    );
}

fn own_verify(temp_path: &TempDir) {
    let path = temp_path.path();
    let message_data = read_file(path.join(MESSAGE_FILE_NAME).to_str().unwrap());
    let signature_data = read_file(path.join(SIGNATURE_FILE_NAME).to_str().unwrap());
    let public_key_data = read_file(path.join(PUBLIC_KEY_NAME).to_str().unwrap());

    assert!(hbs_lms::verify::<Sha256>(
        &message_data,
        &signature_data,
        &public_key_data
    ));
}

fn reference_verify(temp_path: &TempDir) {
    let demo_path = get_demo_path();

    let result = Command::new(&demo_path)
        .args(&["verify", KEY_NAME, MESSAGE_FILE_NAME])
        .current_dir(temp_path)
        .output()
        .expect("Signing should succeed.");

    assert!(result.status.success());
}

fn create_message_file(temp_path: &TempDir) {
    let mut message = std::fs::File::create(temp_path.path().join(MESSAGE_FILE_NAME))
        .expect("Message should be created.");
    message
        .write_all(b"Hello!")
        .expect("File write should succeed.");
}

fn reference_genkey(temp_path: &TempDir) {
    let demo_path = get_demo_path();

    let result = Command::new(&demo_path)
        .args(&["genkey", KEY_NAME, PARAMETER])
        .current_dir(temp_path)
        .output()
        .expect("Reference key generation should succeed.");

    println!(
        "Genkey output: {}",
        String::from_utf8(result.stdout).unwrap()
    );

    assert!(result.status.success());
}

fn reference_genkey_seed(temp_path: &TempDir, seed: &[u8]) {
    let demo_path = get_demo_path();

    let ascii = hex::encode(seed);
    let seed = String::from("seed=") + &ascii;
    let i = String::from("i=") + &ascii;

    let result = Command::new(&demo_path)
        .args(&["genkey", KEY_NAME, PARAMETER, &seed, &i])
        .current_dir(temp_path)
        .output()
        .expect("Reference key generation should succeed.");

    assert!(result.status.success());
}

fn reference_sign(temp_path: &TempDir) {
    let demo_path = get_demo_path();

    let result = Command::new(&demo_path)
        .args(&["sign", KEY_NAME, MESSAGE_FILE_NAME])
        .current_dir(temp_path)
        .output()
        .expect("Reference signing should succeed.");

    println!("Sign output: {}", String::from_utf8(result.stdout).unwrap());

    assert!(result.status.success());
}

fn get_demo_path() -> PathBuf {
    let mut demo_path = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    demo_path.push("tests/demo");
    demo_path
}
