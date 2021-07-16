use clap::{App, Arg, ArgMatches, SubCommand};
use lms::*;
use std::{
    fs::File,
    io::{Read, Write},
    process::exit,
};

type LmsParameterSet = (LmotsParameter, LmsParameter);

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

    let mut private_key_data = read_file(&private_key_name);
    let message_data = read_file(&message_name);

    let result = hss_sign::<Sha256Hasher, 1>(&message_data, &mut private_key_data);

    let result = match result {
        None => {
            print!("Could not sign message.");
            exit(-1)
        }
        Some(x) => x,
    };

    write(&private_key_name, &private_key_data)?;
    write(&signature_name, result.as_slice())?;

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

    // let signature_lmots_type = read_lmots_type_from_signature(&signature_data)
    //     .expect("Signature should have a valid lmots type");
    // let public_key_lmots_type = read_lmots_type_from_public_key(&public_key_data)
    //     .expect("Public key should have a valid lmots type");

    // if signature_lmots_type != public_key_lmots_type {
    //     return false;
    // }

    // let signature_lms_type = read_lms_type_from_signature(&signature_data)
    //     .expect("Signature should have a valid lmots type");
    // let public_key_lms_type = read_lms_type_from_public_key(&public_key_data)
    //     .expect("Public key should have a valid lmots type");

    // if signature_lms_type != public_key_lms_type {
    //     return false;
    // }

    hss_verify::<Sha256Hasher, 1>(&message_data, &signature_data, &public_key_data)
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

    let lm_ots_parameter = parameter.0;
    let lms_parameter = parameter.1;

    let parameter = HssParameter::new(lm_ots_parameter, lms_parameter);

    let keys = hss_keygen::<Sha256Hasher, 1>(&[parameter]);

    let keys = keys.unwrap();

    let public_key_binary = keys.public_key;
    let public_key_filename = get_public_key_name(&keyname);

    let private_key_binary = keys.private_key;
    let private_key_filename = get_private_key_name(&keyname);

    write(public_key_filename.as_str(), &public_key_binary.as_slice())?;
    write(
        private_key_filename.as_str(),
        &private_key_binary.as_slice(),
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
        1 => LmotsAlgorithm::LmotsW1.construct_parameter().unwrap(),
        2 => LmotsAlgorithm::LmotsW2.construct_parameter().unwrap(),
        4 => LmotsAlgorithm::LmotsW4.construct_parameter().unwrap(),
        8 => LmotsAlgorithm::LmotsW8.construct_parameter().unwrap(),
        _ => panic!("Wrong winternitz parameter"),
    };

    let lms = match height {
        5 => LmsAlgorithm::LmsH5.construct_parameter().unwrap(),
        10 => LmsAlgorithm::LmsH10.construct_parameter().unwrap(),
        15 => LmsAlgorithm::LmsH15.construct_parameter().unwrap(),
        20 => LmsAlgorithm::LmsH20.construct_parameter().unwrap(),
        25 => LmsAlgorithm::LmsH25.construct_parameter().unwrap(),
        _ => panic!("Height not supported"),
    };

    (lm_ots, lms)
}

fn write(filename: &str, content: &[u8]) -> Result<(), std::io::Error> {
    let mut file = File::create(filename)?;
    file.write_all(content)?;
    Ok(())
}

// fn read_lmots_type_from_private_key(data: &Vec<u8>) -> Option<LmotsAlgorithmType> {
//     let lm_ots_typecode = &data[4..8];
//     let lm_ots_typecode = str32u(lm_ots_typecode);
//     get_lmots_type(lm_ots_typecode)
// }

// fn read_lmots_type_from_public_key(data: &Vec<u8>) -> Option<LmotsAlgorithmType> {
//     let lm_ots_typecode = &data[8..12];
//     let lm_ots_typecode = str32u(lm_ots_typecode);
//     get_lmots_type(lm_ots_typecode)
// }

// fn read_lmots_type_from_signature(data: &Vec<u8>) -> Option<LmotsAlgorithmType> {
//     let lm_ots_typecode = &data[8..12];
//     let lm_ots_typecode = str32u(lm_ots_typecode);
//     get_lmots_type(lm_ots_typecode)
// }

// fn get_lmots_type(lm_ots_typecode: u32) -> Option<LmotsAlgorithmType> {
//     match lm_ots_typecode {
//         1 => Some(LmotsAlgorithmType::LmotsSha256N32W1),
//         2 => Some(LmotsAlgorithmType::LmotsSha256N32W2),
//         3 => Some(LmotsAlgorithmType::LmotsSha256N32W4),
//         4 => Some(LmotsAlgorithmType::LmotsSha256N32W8),
//         _ => None,
//     }
// }

// fn read_lms_type_from_private_key(data: &Vec<u8>) -> Option<LmsAlgorithmType> {
//     let lm_ots_typecode = &data[0..4];
//     let lm_ots_typecode = str32u(lm_ots_typecode);
//     get_lms_type(lm_ots_typecode)
// }

// fn read_lms_type_from_public_key(data: &Vec<u8>) -> Option<LmsAlgorithmType> {
//     let lm_ots_typecode = &data[4..8];
//     let lm_ots_typecode = str32u(lm_ots_typecode);
//     get_lms_type(lm_ots_typecode)
// }

// fn read_lms_type_from_signature(data: &Vec<u8>) -> Option<LmsAlgorithmType> {
//     let lm_ots_type = read_lmots_type_from_signature(data)?;

//     // Stupid... Need better solution
//     let p = match lm_ots_type {
//         LmotsAlgorithmType::LmotsSha256N32W1 => <LmotsSha256N32W1>::get_p(),
//         LmotsAlgorithmType::LmotsSha256N32W2 => <LmotsSha256N32W2>::get_p(),
//         LmotsAlgorithmType::LmotsSha256N32W4 => <LmotsSha256N32W4>::get_p(),
//         LmotsAlgorithmType::LmotsSha256N32W8 => <LmotsSha256N32W8>::get_p(),
//     };

//     // Stupid... Need better solution
//     let n = match lm_ots_type {
//         LmotsAlgorithmType::LmotsSha256N32W1 => <LmotsSha256N32W1>::N,
//         LmotsAlgorithmType::LmotsSha256N32W2 => <LmotsSha256N32W2>::N,
//         LmotsAlgorithmType::LmotsSha256N32W4 => <LmotsSha256N32W4>::N,
//         LmotsAlgorithmType::LmotsSha256N32W8 => <LmotsSha256N32W8>::N,
//     };

//     let lms_type_start = 4 + 8 + n as usize * (p as usize + 1);
//     let lms_type_end = 4 + 11 + n as usize * (p as usize + 1);

//     let lm_ots_typecode = &data[lms_type_start..=lms_type_end];
//     let lm_ots_typecode = str32u(lm_ots_typecode);
//     get_lms_type(lm_ots_typecode)
// }

// fn get_lms_type(lm_ots_typecode: u32) -> Option<LmsAlgorithmType> {
//     match lm_ots_typecode {
//         5 => Some(LmsAlgorithmType::LmsSha256M32H5),
//         6 => Some(LmsAlgorithmType::LmsSha256M32H10),
//         7 => Some(LmsAlgorithmType::LmsSha256M32H15),
//         8 => Some(LmsAlgorithmType::LmsSha256M32H20),
//         9 => Some(LmsAlgorithmType::LmsSha256M32H25),
//         _ => None,
//     }
// }

// fn str32u(x: &[u8]) -> u32 {
//     let arr: [u8; 4] = x.try_into().expect("Slice not 4 bytes long");
//     u32::from_be_bytes(arr)
// }
