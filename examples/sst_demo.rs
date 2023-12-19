use clap::{Arg, ArgMatches, Command};
use hbs_lms::*;
use std::{
    error::Error,
    fmt,
    fs::{read, File},
    io::{Read, Write},
    process::exit,
};
use tinyvec::ArrayVec;

const GENKEY_COMMAND: &str = "genkey";
const VERIFY_COMMAND: &str = "verify";
const SIGN_COMMAND: &str = "sign";

#[cfg(feature = "fast_verify")]
const SIGN_MUT_COMMAND: &str = "sign_mut";

const ARG_KEYNAME: &str = "keyname";
const ARG_MESSAGE: &str = "file";
const ARG_SSTS_PARAMETER: &str = "parameter";
const ARG_SEED: &str = "seed";

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
    pub fn raise<R>(message: String) -> Result<R, Box<dyn Error>> {
        Err(Box::new(Self(message)))
    }
}

type Hasher = Sha256_256;

struct GenKeyParameter {
    parameter: SstsParameter<Hasher>,
    aux_data: usize,
}

impl GenKeyParameter {
    pub fn new(parameter: SstsParameter<Hasher>, aux_data: Option<usize>) -> Self {
        let aux_data = aux_data.unwrap_or(AUX_DATA_DEFAULT_SIZE);
        Self {
            parameter,
            aux_data,
        }
    }
}


fn main() -> Result<(), Box<dyn std::error::Error>> {

    let message = [32; 0]; // 32 elements init. with 0
    let _hss_key = match hbs_lms::sst::gen_sst_subtree() {
        // save aux data here or in gen_sst_subtree()? -> rather here, compare with lms-demo
        Ok(_) => println!("sst::gen_sst_subtree OK"),
        Err(error) => panic!("sst::gen_sst_subtree error {:?}", error),
    };

    let _sst_pubkey = match hbs_lms::sst::gen_sst_pubkey() {
        Ok(_) => println!("sst::gen_key OK"),
        Err(error) => panic!("sst::gen_key: error {:?}", error),
    };

    let _signature = match hbs_lms::sst::sign::<Hasher>(&message) {
        Ok(_) => println!("sst::sign OK"),
        Err(error) => panic!("sst::sign {:?}", error),
    };

    let signature = [32; 0]; // 32 elements init. with 0
    let public_key = [32; 0]; // 32 elements init. with 0
    if hbs_lms::sst::verify::<Hasher>(&message, &signature, &public_key) == false {
        println!("sst::verify failed");
        exit(1);
    }

    println!("sst::verify OK");


    // ********** code from "lms-demo.rs" to steal/import parameter parsing etc. **********
    let command = Command::new("SSTS Demo")
    .about("Generates SSTS keys and uses them for signing and verifying.")
    .subcommand(
        Command::new(GENKEY_COMMAND)
            .arg(Arg::new(ARG_KEYNAME).required(true))
            .arg(Arg::new(ARG_SSTS_PARAMETER).required(true).help(
                "Specify LMS parameters (e.g. 5/4/2 (tree height 5, Winternitz parameter 4, top height 2))"))
            .arg(Arg::new(ARG_SEED).long(ARG_SEED).required(true).takes_value(true).value_name("seed")),
    )
    .subcommand(
        Command::new(VERIFY_COMMAND)
        .arg(Arg::new(ARG_KEYNAME).required(true))
        .arg(Arg::new(ARG_MESSAGE).required(true).help("File to verify")))
    .subcommand(
        Command::new(SIGN_COMMAND)
        .arg(Arg::new(ARG_KEYNAME).required(true))
        .arg(Arg::new(ARG_MESSAGE).required(true))
    );

    #[cfg(feature = "fast_verify")]
    let command = command.subcommand(
        Command::new(SIGN_MUT_COMMAND)
            .arg(Arg::new(ARG_KEYNAME).required(true))
            .arg(Arg::new(ARG_MESSAGE).required(true)),
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
    let keyname = get_parameter(ARG_KEYNAME, args);
    let message_name = get_parameter(ARG_MESSAGE, args);

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
        hbs_lms::sign::<Hasher>(
            &message_data,
            &private_key_data,
            &mut private_key_update_function,
            Some(aux_slice),
        )
    } else {
        hbs_lms::sign::<Hasher>(
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
    let keyname = get_parameter(ARG_KEYNAME, args);
    let message_name = get_parameter(ARG_MESSAGE, args);

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
        hbs_lms::sign_mut::<Hasher>(
            &mut message_data,
            &private_key_data,
            &mut private_key_update_function,
            Some(aux_slice),
        )
    } else {
        hbs_lms::sign_mut::<Hasher>(
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
    let keyname: String = get_parameter(ARG_KEYNAME, args);
    let message_name: String = get_parameter(ARG_MESSAGE, args);

    let public_key_name = get_public_key_name(&keyname);
    let signature_name = get_signature_name(&message_name);

    let signature_data = read_file(&signature_name);
    let message_data = read_file(&message_name);
    let public_key_data = read_file(&public_key_name);

    hbs_lms::verify::<Hasher>(&message_data, &signature_data, &public_key_data).is_ok()
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
    let keyname: String = get_parameter(ARG_KEYNAME, args);

    let genkey_parameter = parse_genkey_parameter(&get_parameter(ARG_SSTS_PARAMETER, args));
    let parameter = genkey_parameter.parameter;

    let seed: Seed<Hasher> = if let Some(seed) = args.value_of(ARG_SEED) {
        let decoded = hex::decode(seed)?;
        if decoded.len() < Hasher::OUTPUT_SIZE as usize {
            let error = format!(
                "Seed is too short ({} of {} required bytes)",
                decoded.len(),
                Hasher::OUTPUT_SIZE
            );
            return DemoError::raise(error);
        }
        let mut seed = Seed::default();
        seed.as_mut_slice().copy_from_slice(&decoded[..]);
        seed
    } else {
        return DemoError::raise("Seed was not given".to_string());
    };

    let mut aux_data = vec![0u8; genkey_parameter.aux_data];
    let aux_slice: &mut &mut [u8] = &mut &mut aux_data[..];

    // to fix for time being, provide HssParameter param as vector
    let hss_params= parameter.get_hss_parameters();

    let (signing_key, verifying_key) = keygen(hss_params, &seed, Some(aux_slice))
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
    let mut vec_hss_params: ArrayVec<[_; 5]> = Default::default();

    let mut aux_data_size: Option<usize> = None;
    let mut top_part_height : u8 = 0; // @TODO later as option

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

    // "," is supposed to split several HSS levels; 10/2,10/2,10/2 for three levels with tree=10 and w=2
    let parameters = parameter.split(',');

    for parameter in parameters {
        // for now we check and abort if several HSS params provided; leave the HSS-param-loop for use in future
        if vec_hss_params.len() >= 1 {
            break;
        }

        let mut splitted = parameter.split('/');

        let height = splitted
            .next()
            .expect("Merkle tree height invalid");
        let winternitz_parameter = splitted
            .next()
            .expect("Winternitz parameter invalid");
        let tmp_top_part_height = splitted
            .next()
            .expect("Top part height invalid");

        let height: u8 = height
            .parse()
            .expect("Merkle tree height invalid");
        let winternitz_parameter: u8 = winternitz_parameter
            .parse()
            .expect("Winternitz parameter not correct specified");

        top_part_height = tmp_top_part_height
            .parse()
            .expect("Top part height invalid");

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

        let hss_parameters = HssParameter::new(lm_ots, lms);
        vec_hss_params.push(hss_parameters);
    }

    let ssts_param = SstsParameter::new(vec_hss_params, top_part_height);

    GenKeyParameter::new(ssts_param, aux_data_size)
}

fn write(filename: &str, content: &[u8]) -> Result<(), std::io::Error> {
    let mut file = File::create(filename)?;
    file.write_all(content)?;
    Ok(())
}
