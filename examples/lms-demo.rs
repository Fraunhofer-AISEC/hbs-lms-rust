use clap::{App, Arg, ArgMatches, SubCommand};
use hbs_lms::*;
use std::{
    error::Error,
    fmt,
    fs::{read, File},
    io::{Read, Write},
    mem::size_of,
    process::exit,
};

const GENKEY_COMMAND: &str = "genkey";
const VERIFY_COMMAND: &str = "verify";
const SIGN_COMMAND: &str = "sign";

#[cfg(feature = "fast_verify")]
const SIGN_MUT_COMMAND: &str = "sign_mut";

const KEYNAME_PARAMETER: &str = "keyname";
const MESSAGE_PARAMETER: &str = "file";
const PARAMETER_PARAMETER: &str = "parameter";
const SEED_PARAMETER: &str = "seed";

const AUX_DATA_DEFAULT_SIZE: usize = 100_000_000;

#[derive(Debug)]
struct DemoError(String);

impl fmt::Display for DemoError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "There is an error: {}", self.0)
    }
}

impl Error for DemoError {}

impl DemoError {
    pub fn raise<R>(message: &str) -> Result<R, Box<dyn Error>> {
        Err(Box::new(Self(String::from(message))))
    }
}

struct GenKeyParameter {
    parameter: Vec<HssParameter<Sha256Hasher>>,
    aux_data: usize,
}

impl GenKeyParameter {
    pub fn new(parameter: Vec<HssParameter<Sha256Hasher>>, aux_data: Option<usize>) -> Self {
        let aux_data = aux_data.unwrap_or(AUX_DATA_DEFAULT_SIZE);
        Self {
            parameter,
            aux_data,
        }
    }
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let command = App::new("LMS Demo")
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
        );

    #[cfg(feature = "fast_verify")]
    let command = command.subcommand(
        SubCommand::with_name(SIGN_MUT_COMMAND)
            .arg(Arg::with_name(KEYNAME_PARAMETER).required(true))
            .arg(Arg::with_name(MESSAGE_PARAMETER).required(true)),
    );

    let matches = command.get_matches();

    if let Some(args) = matches.subcommand_matches(GENKEY_COMMAND) {
        genkey(args)?;
        println!("Keys successful generated!");
        return Ok(());
    }

    if let Some(args) = matches.subcommand_matches(VERIFY_COMMAND) {
        let result = verify(args);
        if result {
            println!("Successful!");
            exit(0);
        } else {
            println!("Wrong signature");
            exit(-1);
        }
    }

    if let Some(args) = matches.subcommand_matches(SIGN_COMMAND) {
        sign(args)?;
        println!("Signature successful generated!");
        return Ok(());
    }

    #[cfg(feature = "fast_verify")]
    if let Some(args) = matches.subcommand_matches(SIGN_MUT_COMMAND) {
        sign_mut(args)?;
        println!("Mut signature successful generated!");
        return Ok(());
    }

    Ok(())
}

fn sign(args: &ArgMatches) -> Result<(), std::io::Error> {
    let keyname = get_parameter(KEYNAME_PARAMETER, args);
    let message_name = get_parameter(MESSAGE_PARAMETER, args);

    let private_key_name = get_private_key_name(&keyname);
    let signature_name = get_signature_name(&message_name);

    let private_key_data = read_file(&private_key_name);
    let message_data = read_file(&message_name);

    let aux_data_name = get_aux_name(&keyname);
    let mut aux_data = read(aux_data_name).ok();

    let mut private_key_update_function = |new_key: &[u8]| {
        if write(&private_key_name, new_key).is_ok() {
            return Ok(());
        }
        Err(())
    };

    let result = if let Some(aux_data) = aux_data.as_mut() {
        let aux_slice = &mut &mut aux_data[..];
        hbs_lms::sign::<Sha256Hasher>(
            &message_data,
            &private_key_data,
            &mut private_key_update_function,
            Some(aux_slice),
        )
    } else {
        hbs_lms::sign::<Sha256Hasher>(
            &message_data,
            &private_key_data,
            &mut private_key_update_function,
            None,
        )
    };

    if result.is_err() {
        println!("Could not sign message.");
        exit(-1)
    }

    write(&signature_name, result.unwrap().as_ref())?;

    Ok(())
}

#[cfg(feature = "fast_verify")]
fn sign_mut(args: &ArgMatches) -> Result<(), std::io::Error> {
    let keyname = get_parameter(KEYNAME_PARAMETER, args);
    let message_name = get_parameter(MESSAGE_PARAMETER, args);

    let private_key_name = get_private_key_name(&keyname);

    let signature_name_mut = get_signature_mut_name(&message_name);
    let message_name_mut = get_message_mut_name(&message_name);

    let private_key_data = read_file(&private_key_name);

    let mut message_data = read_file(&message_name);
    message_data.extend_from_slice(&[0u8; 32]);

    let aux_data_name = get_aux_name(&keyname);
    let mut aux_data = read(aux_data_name).ok();

    let mut private_key_update_function = |new_key: &[u8]| {
        if write(&private_key_name, new_key).is_ok() {
            return Ok(());
        }
        Err(())
    };

    let signature_result = if let Some(aux_data) = aux_data.as_mut() {
        let aux_slice = &mut &mut aux_data[..];
        hbs_lms::sign_mut::<Sha256Hasher>(
            &mut message_data,
            &private_key_data,
            &mut private_key_update_function,
            Some(aux_slice),
        )
    } else {
        hbs_lms::sign_mut::<Sha256Hasher>(
            &mut message_data,
            &private_key_data,
            &mut private_key_update_function,
            None,
        )
    };

    if signature_result.is_err() {
        println!("Could not sign message.");
        exit(-1)
    }
    let signature = signature_result.unwrap();

    write(&signature_name_mut, signature.as_ref())?;
    write(&message_name_mut, &message_data)?;

    #[cfg(feature = "verbose")]
    println!(
        "fast_verify needed {} iterations.",
        signature.hash_iterations
    );

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

    hbs_lms::verify::<Sha256Hasher>(&message_data, &signature_data, &public_key_data)
}

fn get_public_key_name(keyname: &str) -> String {
    keyname.to_string() + ".pub"
}

fn get_signature_name(message_name: &str) -> String {
    message_name.to_string() + ".sig"
}

#[cfg(feature = "fast_verify")]
fn get_signature_mut_name(message_name: &str) -> String {
    message_name.to_string() + "_mut.sig"
}

#[cfg(feature = "fast_verify")]
fn get_message_mut_name(message_name: &str) -> String {
    message_name.to_string() + "_mut"
}

fn get_private_key_name(private_key: &str) -> String {
    private_key.to_string() + ".prv"
}

fn get_aux_name(keyname: &str) -> String {
    keyname.to_string() + ".aux"
}

fn get_parameter(name: &str, args: &ArgMatches) -> String {
    args.value_of(name)
        .expect("Parameter must be present.")
        .into()
}

fn read_file(file_name: &str) -> Vec<u8> {
    let mut file = std::fs::File::open(file_name)
        .unwrap_or_else(|_| panic!("Could not read data from: {}", file_name));

    let mut data: Vec<u8> = Vec::new();
    file.read_to_end(&mut data)
        .unwrap_or_else(|_| panic!("Could not read data from: {}", file_name));

    data
}

fn genkey(args: &ArgMatches) -> Result<(), Box<dyn std::error::Error>> {
    let keyname: String = get_parameter(KEYNAME_PARAMETER, args);

    let genkey_parameter = parse_genkey_parameter(&get_parameter(PARAMETER_PARAMETER, args));
    let parameter = genkey_parameter.parameter;

    let seed: Seed = if let Some(seed) = args.value_of(SEED_PARAMETER) {
        let decoded = hex::decode(seed)?;
        if decoded.len() < size_of::<Seed>() {
            return DemoError::raise("Seed is too short");
        }
        let mut seed = Seed::default();
        seed.copy_from_slice(&decoded[..]);
        seed
    } else {
        return DemoError::raise("Seed was not given");
    };

    let mut aux_data = vec![0u8; genkey_parameter.aux_data];
    let aux_slice: &mut &mut [u8] = &mut &mut aux_data[..];

    let (signing_key, verifying_key) = keygen(&parameter, &seed, Some(aux_slice))
        .unwrap_or_else(|_| panic!("Could not generate keys"));

    let public_key_filename = get_public_key_name(&keyname);
    let private_key_filename = get_private_key_name(&keyname);

    let aux_name = get_aux_name(&keyname);
    write(&aux_name, aux_slice)?;

    write(public_key_filename.as_str(), verifying_key.as_slice())?;
    write(private_key_filename.as_str(), signing_key.as_slice())?;

    Ok(())
}

fn parse_genkey_parameter(parameter: &str) -> GenKeyParameter {
    let mut result = Vec::new();

    let mut aux_data_size: Option<usize> = None;

    let parameter = if parameter.contains(':') {
        let mut splitted = parameter.split(':');
        let parameter = splitted.next().expect("Should contain parameter");

        let aux_data = splitted.next().expect("Should contain aux data size");
        let aux_data = aux_data
            .parse::<usize>()
            .expect("Could not parse aux data size");
        aux_data_size = Some(aux_data);

        parameter
    } else {
        parameter
    };

    let parameters = parameter.split(',');

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
            1 => LmotsAlgorithm::LmotsW1,
            2 => LmotsAlgorithm::LmotsW2,
            4 => LmotsAlgorithm::LmotsW4,
            8 => LmotsAlgorithm::LmotsW8,
            _ => panic!("Wrong winternitz parameter"),
        };

        let lms = match height {
            5 => LmsAlgorithm::LmsH5,
            10 => LmsAlgorithm::LmsH10,
            15 => LmsAlgorithm::LmsH15,
            20 => LmsAlgorithm::LmsH20,
            25 => LmsAlgorithm::LmsH25,
            _ => panic!("Height not supported"),
        };

        let parameter = HssParameter::new(lm_ots, lms);
        result.push(parameter);
    }

    GenKeyParameter::new(result, aux_data_size)
}

fn write(filename: &str, content: &[u8]) -> Result<(), std::io::Error> {
    let mut file = File::create(filename)?;
    file.write_all(content)?;
    Ok(())
}
