use clap::{App, Arg, ArgMatches, SubCommand};
use lms::{hss_keygen, hss_sign, hss_verify, LmotsAlgorithmType, LmsAlgorithmType};
use std::{
    fs::File,
    io::{Read, Write},
    process::exit,
};

type LmsParameterSet = (LmotsAlgorithmType, LmsAlgorithmType);

const GENKEY_COMMAND: &str = "genkey";
const VERIFY_COMMAND: &str = "verify";
const SIGN_COMMAND: &str = "sign";

const KEYNAME_PARAMETER: &str = "keyname";
const MESSAGE_PARAMETER: &str = "file";
const PARAMETER_PARAMETER: &str = "parameter";

fn main() -> Result<(), std::io::Error> {
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
        .subcommand(
            SubCommand::with_name(SIGN_COMMAND)
            .arg(Arg::with_name(KEYNAME_PARAMETER).required(true))
            .arg(Arg::with_name(MESSAGE_PARAMETER).required(true))
        )
        .get_matches();

    if let Some(args) = matches.subcommand_matches(GENKEY_COMMAND) {
        genkey(args)?;
        print!("Keys successful generated!");
        return Ok(());
    }

    if let Some(args) = matches.subcommand_matches(VERIFY_COMMAND) {
        let result = verify(args);
        if result == true {
            print!("Successful!");
            exit(0);
        } else {
            print!("Wrong signature");
            exit(-1);
        }
    }

    if let Some(args) = matches.subcommand_matches(SIGN_COMMAND) {
        sign(args)?;
        print!("Signature successful generated!");
        return Ok(());
    }

    Ok(())
}

fn sign(args: &ArgMatches) -> Result<(), std::io::Error> {
    let keyname = get_parameter(KEYNAME_PARAMETER, args);
    let message_name = get_parameter(MESSAGE_PARAMETER, args);

    let private_key_name = get_private_key_name(&keyname);
    let signature_name = get_signature_name(&message_name);

    let private_key_data = read_file(&&private_key_name);
    let message_data = read_file(&message_name);

    let result = match hss_sign(&message_data, &private_key_data) {
        None => {
            print!("Could not sign message.");
            exit(-1)
        }
        Some(x) => x,
    };

    write(&private_key_name, &result.advanced_private_key.get_slice())?;
    write(&signature_name, &result.signature.get_slice())?;

    Ok(())
}

fn verify(args: &ArgMatches) -> bool {
    let keyname: String = get_parameter(KEYNAME_PARAMETER, args);
    let message_name: String = get_parameter(MESSAGE_PARAMETER, args);

    let public_key_name = get_public_key_name(&keyname);
    let signature_name = get_signature_name(&message_name);

    let signature_data = read_file(&signature_name);
    let message_data = read_file(&message_name);
    let public_key_data = read_file(&public_key_name);

    hss_verify(&message_data, &signature_data, &public_key_data)
}

fn get_public_key_name(keyname: &String) -> String {
    keyname.clone() + ".pub"
}

fn get_signature_name(message_name: &String) -> String {
    message_name.clone() + ".sig"
}

fn get_private_key_name(private_key: &String) -> String {
    private_key.clone() + ".priv"
}

fn get_parameter(name: &str, args: &ArgMatches) -> String {
    args.value_of(name)
        .expect("Parameter must be present.")
        .into()
}

fn read_file(file_name: &str) -> Vec<u8> {
    let mut file = std::fs::File::open(file_name)
        .expect(format!("Could not open file: {}", file_name).as_str());

    let mut data: Vec<u8> = Vec::new();
    file.read_to_end(&mut data)
        .expect(format!("Could not read data from: {}", file_name).as_str());

    data
}

fn genkey(args: &ArgMatches) -> Result<(), std::io::Error> {
    let keyname: String = get_parameter(KEYNAME_PARAMETER, args);

    let parameter = parse_genkey_parameter(&get_parameter(PARAMETER_PARAMETER, args));

    let lm_ots_parameter_type = parameter.0;
    let lms_parameter_type = parameter.1;

    let keys = hss_keygen(lms_parameter_type, lm_ots_parameter_type);

    let public_key_binary = keys.public_key;
    let public_key_filename = get_public_key_name(&keyname);

    let private_key_binary = keys.private_key;
    let private_key_filename = get_private_key_name(&keyname);

    write(public_key_filename.as_str(), &public_key_binary.get_slice())?;
    write(
        private_key_filename.as_str(),
        &private_key_binary.get_slice(),
    )?;

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
    file.write_all(content)?;
    Ok(())
}
