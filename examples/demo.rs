extern crate lms;

use clap::{App, Arg, ArgMatches, SubCommand};
use lms::*;
use std::{
    fs::File,
    io::{Read, Write},
};

type LmsParameterSet = (LmotsAlgorithmType, LmsAlgorithmType);

const GENKEY_COMMAND: &str = "genkey";
const VERIFY_COMMAND: &str = "verify";

const KEYNAME_PARAMETER: &str = "keyname";
const MESSAGE_PARAMETER: &str = "file";
const PARAMETER_PARAMETER: &str = "parameter";

fn main() {
    let matches = App::new("LMS Demo")
        .about("Generates a LMS key pair")
        .subcommand(
            SubCommand::with_name(GENKEY_COMMAND)
                .arg(Arg::with_name(KEYNAME_PARAMETER).required(true))
                .arg(Arg::with_name(PARAMETER_PARAMETER).required(false).help(
                    "Specify LMS parameters (e.g. 15/4 (Treeheight 15 and Winternitz parameter 4))",
                ).default_value("5/1")),
        )
        .subcommand(
            SubCommand::with_name(VERIFY_COMMAND)
            .arg(Arg::with_name(KEYNAME_PARAMETER).required(true))
            .arg(Arg::with_name(MESSAGE_PARAMETER).required(true).help("File to verify")))
        .get_matches();

    if let Some(args) = matches.subcommand_matches(GENKEY_COMMAND) {
        genkey(args).expect("Could not generate key pair.");
        return;
    }

    if let Some(args) = matches.subcommand_matches(VERIFY_COMMAND) {
        let result = verify(args);
        if result == true {
            print!("Successful!");
        } else {
            print!("Wrong signature");
        }
        return;
    }
}

fn verify(args: &ArgMatches) -> bool {
    let keyname: String = args
        .value_of(KEYNAME_PARAMETER)
        .expect("Keyname must be present.")
        .into();

    let message_name: String = args
        .value_of(MESSAGE_PARAMETER)
        .expect("Message must be present")
        .into();

    let public_key_name = keyname.clone() + ".pub";
    let signature_name = message_name.clone() + ".sig";

    let signature_data = read_file(&signature_name);
    let message_data = read_file(&message_name);
    let public_key_data = read_file(&public_key_name);

    lms::verify(&message_data, &signature_data, &public_key_data)
}

fn read_file(file_name: &str) -> Vec<u8> {
    let mut file = std::fs::File::open(file_name)
        .expect(format!("Could not open file: {}", file_name).as_str());

    let mut data: Vec<u8> = Vec::new();
    file.read(&mut data)
        .expect(format!("Could not read data from: {}", file_name).as_str());

    data
}

fn genkey(args: &ArgMatches) -> Result<(), std::io::Error> {
    let keyname: String = args
        .value_of(KEYNAME_PARAMETER)
        .expect("Keyname must be present")
        .into();
    let parameter = parse_genkey_parameter(
        args.value_of(PARAMETER_PARAMETER)
            .expect("Default parameter must be specified."),
    );

    let lm_ots_parameter_type = parameter.0;
    let lms_parameter_type = parameter.1;

    let private_key = lms::generate_private_key(lms_parameter_type, lm_ots_parameter_type);
    let public_key = lms::generate_public_key(&private_key);

    let public_key_binary = public_key.to_binary_representation();
    let public_key_filename = keyname.clone() + ".pub";

    let private_key_binary = private_key.to_binary_representation();
    let private_key_filename = keyname.clone() + ".priv";

    write(public_key_filename.as_str(), &public_key_binary)?;
    write(private_key_filename.as_str(), &private_key_binary)?;

    Ok(())
}

fn parse_genkey_parameter(parameter: &str) -> LmsParameterSet {
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

fn write(filename: &str, content: &[u8]) -> Result<(), std::io::Error> {
    let mut file = File::create(filename)?;
    file.write(content)?;
    Ok(())
}
