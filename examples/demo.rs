extern crate lms;

use lms::*;
use std::{env, fs::File, io::Write};

const DEFAULT_LM_OTS_PARAMETER: LmotsAlgorithmType = LmotsAlgorithmType::LmotsSha256N32W1;
const DEFAULT_LMS_PARAMETER: LmsAlgorithmType = LmsAlgorithmType::LmsSha256M32H5;

type LmsParameterSet = (LmotsAlgorithmType, LmsAlgorithmType);

fn main() {
    let args = env::args();

    if args.len() == 1 {
        usage();
        return;
    }

    let operation = env::args().skip(1).next().expect("Expect a operation");    

    match operation.as_str() {
        "genkey" => genkey(
            env::args().next().expect("Keyname must be present."),
            parse_genkey_parameter(env::args().next()),
        ),
        _ => {
            usage();
            return;
        }
    }
}

fn genkey(keyname: String, parameter: LmsParameterSet) {
    let lm_ots_parameter_type = parameter.0;
    let lms_parameter_type = parameter.1;

    let private_key = lms::generate_private_key(lms_parameter_type, lm_ots_parameter_type);
    let public_key = lms::generate_public_key(&private_key);

    let public_key_binary = public_key.to_binary_representation();

    let mut file = File::create(keyname + ".pub").expect("Could not create public key file.");
    file.write(&public_key_binary).expect("Public key could not be written");
}

fn parse_genkey_parameter(parameter: Option<String>) -> LmsParameterSet {
    if parameter.is_none() {
        return (DEFAULT_LM_OTS_PARAMETER, DEFAULT_LMS_PARAMETER);
    }
    let parameter = parameter.unwrap();
    let mut splitted = parameter.split('/');

    let height = splitted
        .next()
        .expect("Merkle tree height not correct specified");
    let winternitz_parameter = splitted
        .next()
        .expect("Winternitz parameter not correct specified");

    let height: u8 = height
        .parse()
        .expect("Merkle tree height not correct specified");
    let winternitz_parameter: u8 = winternitz_parameter
        .parse()
        .expect("Winternitz parameter not correct specified");

    let lm_ots = match winternitz_parameter {
        1 => LmotsAlgorithmType::LmotsSha256N32W1,
        2 => LmotsAlgorithmType::LmotsSha256N32W2,
        4 => LmotsAlgorithmType::LmotsSha256N32W4,
        8 => LmotsAlgorithmType::LmotsSha256N32W8,
        _ => panic!("Wrong winternitz parameter"),
    };

    let lms = match height {
        5 => LmsAlgorithmType::LmsSha256M32H5,
        10 => LmsAlgorithmType::LmsSha256M32H10,
        15 => LmsAlgorithmType::LmsSha256M32H15,
        20 => LmsAlgorithmType::LmsSha256M32H20,
        25 => LmsAlgorithmType::LmsSha256M32H25,
        _ => panic!("Height not supported"),
    };

    (lm_ots, lms)
}

fn usage() {
    println!("Usage: ");
    println!("demo genkey keyname \t\t// Generate a new key with the name 'keyname' and default parameter: merkle tree height 5 and Winternitz parameter 1");
    println!("demo genkey keyname 15/4 \t// Generate a new key with the name 'keyname' and merkle tree height 15 and Winternitz parameter 4");
}
