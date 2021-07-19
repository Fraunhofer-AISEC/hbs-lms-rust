use clap::{App, Arg, ArgMatches, SubCommand};
use lms::*;
use std::{
    error::Error,
    fmt,
    fs::File,
    io::{Read, Write},
    mem::size_of,
    process::exit,
};

const GENKEY_COMMAND: &str = "genkey";
const VERIFY_COMMAND: &str = "verify";
const SIGN_COMMAND: &str = "sign";

const KEYNAME_PARAMETER: &str = "keyname";
const MESSAGE_PARAMETER: &str = "file";
const PARAMETER_PARAMETER: &str = "parameter";
const SEED_PARAMETER: &str = "seed";

#[derive(Debug)]
struct DemoError(String);

impl fmt::Display for DemoError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "There is an error: {}", self.0)
    }
}

impl Error for DemoError {}

impl DemoError {
    pub fn new<R>(message: &str) -> Result<R, Box<dyn Error>> {
        Err(Box::new(Self(String::from(message))))
    }
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let matches = App::new("LMS Demo")
        .about("Generates a LMS key pair")
        .subcommand(
            SubCommand::with_name(GENKEY_COMMAND)
                .arg(Arg::with_name(KEYNAME_PARAMETER).required(true))
                .arg(Arg::with_name(PARAMETER_PARAMETER).required(false).help(
                    "Specify LMS parameters (e.g. 15/4 (Treeheight 15 and Winternitz parameter 4))",
                ).default_value("5/1"))
                .arg(Arg::with_name(SEED_PARAMETER).long(SEED_PARAMETER).required(false).takes_value(true).value_name("seed")),
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

    let result = hss_sign::<Sha256Hasher>(&message_data, &mut private_key_data);

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

    hss_verify::<Sha256Hasher>(&message_data, &signature_data, &public_key_data)
}

fn get_public_key_name(keyname: &String) -> String {
    keyname.clone() + ".pub"
}

fn get_signature_name(message_name: &String) -> String {
    message_name.clone() + ".sig"
}

fn get_private_key_name(private_key: &String) -> String {
    private_key.clone() + ".prv"
}

fn get_aux_name(keyname: &String) -> String {
    keyname.clone() + ".aux"
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

fn genkey(args: &ArgMatches) -> Result<(), Box<dyn std::error::Error>> {
    let keyname: String = get_parameter(KEYNAME_PARAMETER, args);

    let parameter = parse_genkey_parameter(&get_parameter(PARAMETER_PARAMETER, args));

    let seed = if let Some(seed) = args.value_of(SEED_PARAMETER) {
        let decoded = hex::decode(seed)?;
        if decoded.len() < size_of::<Seed>() {
            return DemoError::new("Seed is too short");
        }
        Some(decoded)
    } else {
        None
    };

    let mut aux_data = vec![0u8; 2000];
    let aux_slice: &mut &mut [u8] = &mut &mut aux_data[..];

    let keys = if let Some(ref seed) = seed {
        hss_keygen_with_seed_and_aux(&parameter, seed, aux_slice)
    } else {
        hss_keygen::<Sha256Hasher>(&parameter)
    };

    let keys = keys.unwrap();

    let public_key_binary = keys.public_key;
    let public_key_filename = get_public_key_name(&keyname);

    let private_key_binary = keys.private_key;
    let private_key_filename = get_private_key_name(&keyname);

    let aux_name = get_aux_name(&keyname);

    if seed.is_some() {
        write(&aux_name, aux_slice)?;
    }

    write(public_key_filename.as_str(), &public_key_binary.as_slice())?;
    write(
        private_key_filename.as_str(),
        &private_key_binary.as_slice(),
    )?;

    Ok(())
}

fn parse_genkey_parameter(parameter: &str) -> Vec<HssParameter<Sha256Hasher>> {
    let mut result = Vec::new();

    let parameters = parameter.split(",");

    for parameter in parameters {
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
            1 => LmotsAlgorithm::LmotsW1
                .construct_parameter::<Sha256Hasher>()
                .unwrap(),
            2 => LmotsAlgorithm::LmotsW2.construct_parameter().unwrap(),
            4 => LmotsAlgorithm::LmotsW4.construct_parameter().unwrap(),
            8 => LmotsAlgorithm::LmotsW8.construct_parameter().unwrap(),
            _ => panic!("Wrong winternitz parameter"),
        };

        let lms = match height {
            5 => LmsAlgorithm::LmsH5
                .construct_parameter::<Sha256Hasher>()
                .unwrap(),
            10 => LmsAlgorithm::LmsH10.construct_parameter().unwrap(),
            15 => LmsAlgorithm::LmsH15.construct_parameter().unwrap(),
            20 => LmsAlgorithm::LmsH20.construct_parameter().unwrap(),
            25 => LmsAlgorithm::LmsH25.construct_parameter().unwrap(),
            _ => panic!("Height not supported"),
        };

        let parameter = HssParameter::new(lm_ots, lms);
        result.push(parameter);
    }

    result
}

fn write(filename: &str, content: &[u8]) -> Result<(), std::io::Error> {
    let mut file = File::create(filename)?;
    file.write_all(content)?;
    Ok(())
}
