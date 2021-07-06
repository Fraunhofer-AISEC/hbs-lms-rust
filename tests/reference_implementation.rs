use std::{
    io::{Read, Write},
    path::PathBuf,
    process::Command,
};

use lms::{hss_keygen, hss_sign, hss_verify, LmotsSha256N32W2, LmsSha256M32H10, LmsSha256M32H5};
use tempfile::TempDir;

const MESSAGE_FILE_NAME: &str = "message.txt";
const SIGNATURE_FILE_NAME: &str = "message.txt.sig";

const KEY_NAME: &str = "testkey";
const PUBLIC_KEY_NAME: &str = "testkey.pub";

#[test]
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
fn create_signature_with_own_implementation() {
    let tempdir = tempfile::tempdir().unwrap();
    let path = tempdir.path();

    let mut keys =
        hss_keygen::<LmotsSha256N32W2, LmsSha256M32H5>().expect("Should create HSS keys");

    save_file(
        path.join(PUBLIC_KEY_NAME).to_str().unwrap(),
        keys.public_key.as_slice(),
    );

    create_message_file(&tempdir);
    let message_data = read_file(path.join(MESSAGE_FILE_NAME).to_str().unwrap());

    own_signing(&tempdir, &message_data, keys.private_key.as_mut_slice());

    reference_verify(&tempdir);

    own_signing(&tempdir, &message_data, keys.private_key.as_mut_slice());

    reference_verify(&tempdir);
}

fn save_file(file_name: &str, data: &[u8]) {
    let mut file = std::fs::File::create(file_name)
        .expect(format!("Could not open file: {}", file_name).as_str());
    file.write_all(data).expect("Could not write file.");
}

fn read_file(file_name: &str) -> Vec<u8> {
    let mut file = std::fs::File::open(file_name)
        .expect(format!("Could not open file: {}", file_name).as_str());

    let mut data: Vec<u8> = Vec::new();
    file.read_to_end(&mut data)
        .expect(format!("Could not read data from: {}", file_name).as_str());

    data
}

fn own_signing(temp_path: &TempDir, message_data: &[u8], private_key: &mut [u8]) {
    let result = hss_sign::<LmotsSha256N32W2, LmsSha256M32H5>(&message_data, private_key)
        .expect("Signing should succed.");
    save_file(
        temp_path.path().join(SIGNATURE_FILE_NAME).to_str().unwrap(),
        result.as_slice(),
    );
}

fn own_verify(temp_path: &TempDir) {
    let path = temp_path.path();
    let message_data = read_file(path.join(MESSAGE_FILE_NAME).to_str().unwrap());
    let signature_data = read_file(path.join(SIGNATURE_FILE_NAME).to_str().unwrap());
    let public_key_data = read_file(path.join(PUBLIC_KEY_NAME).to_str().unwrap());

    assert!(hss_verify::<LmotsSha256N32W2, LmsSha256M32H10>(
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
        .args(&["genkey", KEY_NAME, "10/2"])
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

    assert!(result.status.success());
}

fn get_demo_path() -> PathBuf {
    let mut demo_path = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    demo_path.push("tests/demo");
    demo_path
}
