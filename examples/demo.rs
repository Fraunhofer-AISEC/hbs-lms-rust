extern crate lms;

use clap::{App, Arg, ArgMatches, SubCommand};
use lms::*;
use std::{fs::File, io::Write};

type LmsParameterSet = (LmotsAlgorithmType, LmsAlgorithmType);

fn main() {
    let matches = App::new("LMS Demo")
        .about("Generates a LMS key pair")
        .subcommand(
            SubCommand::with_name("genkey")
                .arg(Arg::with_name("keyname").required(true))
                .arg(Arg::with_name("parameter").required(false).help(
                    "Specify LMS parameters (e.g. 15/4 (Treeheight 15 and Winternitz parameter 4))",
                ).default_value("5/1")),
        )
        .get_matches();

    let args = matches.subcommand_matches("genkey");

    if let Some(args) = args {
        genkey(args).expect("Could not generate key pair.");
    }
}

fn genkey(args: &ArgMatches) -> Result<(), std::io::Error> {
    let keyname: String = args
        .value_of("keyname")
        .expect("Keyname must be present")
        .into();
    let parameter = parse_genkey_parameter(
        args.value_of("parameter")
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
