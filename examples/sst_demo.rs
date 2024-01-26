use clap::{Arg, ArgMatches, Command};
use hbs_lms::*;
use std::{
    error::Error,
    fmt,
    fs::{read, File, OpenOptions},
    io::{Read, Write},
    process::exit,
};
use tinyvec::ArrayVec;

const GENKEY1_COMMAND: &str = "genkey1";
const GENKEY2_COMMAND: &str = "genkey2";
const VERIFY_COMMAND: &str = "verify";
const SIGN_COMMAND: &str = "sign";

#[cfg(feature = "fast_verify")]
const SIGN_MUT_COMMAND: &str = "sign_mut";

const ARG_KEYNAME: &str = "keyname";
const ARG_MESSAGE: &str = "file";
const ARG_HSS_PARAMETER: &str = "parameter";
const ARG_SIGN_ENTITY_IDX_PARAMETER: &str = "se_param";
const ARG_SEED: &str = "seed";
const ARG_AUXSIZE: &str = "auxsize";
const ARG_SSTS_PARAM: &str = "ssts";

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
    ssts_param: SstsParameter<Hasher>,
    aux_data: usize,
}

impl GenKeyParameter {
    pub fn new(ssts_param: SstsParameter<Hasher>, aux_data: Option<usize>) -> Self {
        let aux_data = aux_data.unwrap_or(AUX_DATA_DEFAULT_SIZE);
        Self {
            ssts_param,
            aux_data,
        }
    }
}

fn main() -> Result<(), Box<dyn std::error::Error>> {

    let command = Command::new("SSTS Demo")
    .about("Generates SSTS keys and uses them for signing and verifying.")
    .subcommand(
        Command::new(GENKEY1_COMMAND)
            .arg(Arg::new(ARG_KEYNAME).required(true))
            .arg(Arg::new(ARG_HSS_PARAMETER).required(true).help(
                "Specify LMS parameters (e.g. 10/2 => tree height = 10, Winternitz parameter = 2)"))
            .arg(Arg::new(ARG_SSTS_PARAM).long(ARG_SSTS_PARAM).required(true).takes_value(true).value_name("ssts")
                .help( // TODO allow required = "false"?
                "Specify SSTS parameters (e.g. --ssts=3/8 => signing entity 3 of total 8"))
            .arg(Arg::new(ARG_SEED).long(ARG_SEED).required(true).takes_value(true).value_name("seed")),
    )
    .subcommand(
        Command::new(GENKEY2_COMMAND)
        .arg(Arg::new(ARG_KEYNAME).required(true))
        .arg(Arg::new(ARG_SIGN_ENTITY_IDX_PARAMETER).required(true).help(
            "Specify signing entity index (1..n))"))
        .arg(Arg::new(ARG_AUXSIZE).long(ARG_AUXSIZE).required(false).takes_value(true).value_name("auxsize").help(
            "Specify AUX data size in bytes"))
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

    if let Some(args) = matches.subcommand_matches(GENKEY1_COMMAND) {
        genkey1(args)?;
        println!(
            "Single-subtree-structure: intermediate node and private key successfully generated!"
        );
        return Ok(());
    }

    if let Some(args) = matches.subcommand_matches(GENKEY2_COMMAND) {
        genkey2(args)?;
        println!("Single-subtree-structure: public key successfully generated!");
        return Ok(());
    }

    if let Some(args) = matches.subcommand_matches(SIGN_COMMAND) {
        sign(args)?;
        println!("Signature successfully generated!");
        return Ok(());
    }

    if let Some(args) = matches.subcommand_matches(VERIFY_COMMAND) {
        let result = verify(args);
        if result {
            println!("Verification successful!");
            exit(0);
        } else {
            println!("Wrong signature");
            exit(-1);
        }
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

    let private_key_filename = get_private_key_filename(&keyname, None);
    let signature_filename = get_signature_filename(&message_name);

    let private_key_data = read_file(&private_key_filename);
    let message_data = read_file(&message_name);

    let aux_data_filename = get_aux_filename(&keyname, None);
    let mut aux_data = read(aux_data_filename).ok();

    let mut private_key_update_function = |new_key: &[u8]| {
        if write(&private_key_filename, new_key).is_ok() {
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

    write(&signature_filename, result.unwrap().as_ref())?;

    Ok(())
}

#[cfg(feature = "fast_verify")]
fn sign_mut(args: &ArgMatches) -> Result<(), std::io::Error> {
    let keyname = get_parameter(ARG_KEYNAME, args);
    let message_name = get_parameter(ARG_MESSAGE, args);

    let private_key_name = get_private_key_filename(&keyname);

    let signature_name_mut = get_signature_mut_name(&message_name);
    let message_name_mut = get_message_mut_name(&message_name);

    let private_key_data = read_file(&private_key_name);

    let mut message_data = read_file(&message_name);
    message_data.extend_from_slice(&[0u8; 32]);

    let aux_data_name = get_aux_filename(&keyname);
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

    // TODO: signing entity idx
    let public_key_name = get_public_key_filename(&keyname, None);
    let signature_name = get_signature_filename(&message_name);

    let signature_data = read_file(&signature_name);
    let message_data = read_file(&message_name);
    let public_key_data = read_file(&public_key_name);

    hbs_lms::verify::<Hasher>(&message_data, &signature_data, &public_key_data).is_ok()
}

fn get_public_key_filename(keyname: &str, idx: Option<u8>) -> String {
    if let Some(idx) = idx {
        keyname.to_string() + "." + &idx.to_string() + ".pub"
    } else {
        keyname.to_string() + ".pub"
    }
}

fn get_signature_filename(message_name: &str) -> String {
    message_name.to_string() + ".sig"
}

#[cfg(feature = "fast_verify")]
fn get_signature_mut_filename(message_name: &str) -> String {
    message_name.to_string() + "_mut.sig"
}

#[cfg(feature = "fast_verify")]
fn get_message_mut_filename(message_name: &str) -> String {
    message_name.to_string() + "_mut"
}

fn get_private_key_filename(private_key: &str, idx: Option<u8>) -> String {
    if let Some(idx) = idx {
        private_key.to_string() + "." + &idx.to_string() + ".prv"
    } else {
        private_key.to_string() + ".prv"
    }
}

fn get_aux_filename(keyname: &str, idx: Option<u8>) -> String {
    if let Some(idx) = idx {
        keyname.to_string() + "." + &idx.to_string() + ".aux"
    } else {
        keyname.to_string() + ".aux"
    }
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

fn genkey1(args: &ArgMatches) -> Result<(), Box<dyn std::error::Error>> {
    let keyname: String = get_parameter(ARG_KEYNAME, args);

    let genkey_parameter = parse_genkey1_parameter(
        &get_parameter(ARG_HSS_PARAMETER, args),
        &get_parameter(ARG_SSTS_PARAM, args));

    let ssts_param = genkey_parameter.ssts_param;

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

    // create our private key
    let (signing_key, intermed_node_hashval) =
        genkey1_sst(&ssts_param, &seed, Some(aux_slice)).unwrap_or_else(|_| panic!("Could not generate keys"));

    let private_key_filename = get_private_key_filename(&keyname, Some(ssts_param.get_signing_entity_idx()));
    write(private_key_filename.as_str(), signing_key.as_slice())?;

    // write own node value and signing entity to file
    // TODO     maybe also HSS/LMS/LM-OTS parameters, to ensure that we got the same parameters among all signing entities
    let interm_node_filename = String::from("node_si.")
        + &(ssts_param.get_signing_entity_idx().to_string())
        + &String::from(".bin"); // TODO into function

    // if file exists, overwrite
    write(
        interm_node_filename.as_str(),
        &ssts_param.get_signing_entity_idx().to_be_bytes(),
    )?;
    // and append
    let mut intermed_node_file = OpenOptions::new()
        .create(true)
        .write(true)
        .append(true)
        .open(interm_node_filename.as_str())
        .unwrap();
    intermed_node_file.write_all(intermed_node_hashval.as_slice())?;

    Ok(())
}

fn genkey2(args: &ArgMatches) -> Result<(), Box<dyn std::error::Error>> {
    // get signing entity number and name of private keyfile from args
    let keyname: String = get_parameter(ARG_KEYNAME, args);
    let signing_entity: String = get_parameter(ARG_SIGN_ENTITY_IDX_PARAMETER, args);
    let aux_size: String = get_parameter(ARG_AUXSIZE, args);

    let signing_entity: u8 = signing_entity.parse::<u8>().unwrap();

    // AUX data: currently we create it only in genkey2
    let mut aux_data = vec![0u8; aux_size.parse::<usize>().unwrap()]; // TODO check conversion
    let aux_slice: &mut &mut [u8] = &mut &mut aux_data[..];
    // later on we should create it in genkey1 because it's possibly lots of calculations
    // and in that case we'll read the previously generated aux data from a file

    // println!("keyname: {} -- SI: {} -- aux_size: {}", keyname, signing_entity, aux_size);

    // read private key
    let private_key_name = get_private_key_filename(&keyname, Some(signing_entity));
    let private_key_data = read_file(&private_key_name);

    // here we need one additional API call so we know which files we have to read dep. on HSS config.
    let num_signing_entities = get_num_signing_entities::<Hasher>(&private_key_data)
        .unwrap_or_else(|_| panic!("genkey step 2: invalid config"));

    // TODO maybe compare with HSS configuration in the "node files"
    // read intermediate node values from files (ours and others) and pass for calc.

    let mut node_array: ArrayVec<[ArrayVec<[u8; MAX_HASH_SIZE]>; MAX_DSM_SIGNING_ENTITIES]> =
        Default::default();

    // let mut node_array: ArrayVec<[[u8; MAX_HASH_SIZE]; MAX_DSM_SIGNING_ENTITIES]> = ArrayVec::new();

    for idx in 1..=num_signing_entities {
        let interm_node_filename =
            String::from("node_si.") + &(idx.to_string()) + &String::from(".bin"); // TODO into function

        let file_data: Vec<u8> = read_file(&interm_node_filename);
        if file_data.len() != (1 + MAX_HASH_SIZE) {
            panic!("genkey2(): intermediate node file size is {}, should be {}",
                file_data.len(), (1 + MAX_HASH_SIZE)
            );
        }

        // TODO the following works but is a really bad inefficient solution

        let mut node: [u8; MAX_HASH_SIZE] = [0; MAX_HASH_SIZE];
        node.copy_from_slice(&file_data[1..]);
        node_array.push(node.into());

        // TODO replace with this and adapt calls to functions
        // let node: &[u8; MAX_HASH_SIZE] = file_data[1..].try_into().unwrap();
        // node_array.push(*node);
    }

    let verifying_key = genkey2_sst::<Hasher>(
        &private_key_data,
        &node_array,
        Some(aux_slice),
    ).unwrap_or_else(|_| panic!("Could not generate verifying key"));

    //println!("pub key (node 1) hash value: {:?}", verifying_key);

    let aux_filename: String = get_aux_filename(&keyname, Some(signing_entity));
    write(&aux_filename, aux_slice)?;

    let public_key_filename = get_public_key_filename(&keyname, Some(signing_entity));
    write(public_key_filename.as_str(), verifying_key.as_slice())?;

    Ok(())
}

fn parse_genkey1_parameter(hss_params: &str, ssts_params: &str) -> GenKeyParameter {
    let mut vec_hss_params: ArrayVec<[_; hbs_lms::REF_IMPL_MAX_ALLOWED_HSS_LEVELS]> =
        Default::default();

    let mut aux_data_size: Option<usize> = None;

    // TODO change : use "--auxsize" as cur. in genkey2, then read size in genkey2 from actual filesize
    let hss_params = if hss_params.contains(':') {
        let mut splitted = hss_params.split(':');
        let parameter = splitted.next().expect("Should contain parameter");

        let aux_data = splitted.next().expect("Should contain aux data size");
        let aux_data = aux_data
            .parse::<usize>()
            .expect("Could not parse aux data size");
        aux_data_size = Some(aux_data);

        parameter
    } else {
        hss_params
    };

    let hss_params = hss_params.split(',');

    for hss_param in hss_params {
        let mut splitted = hss_param.split('/');

        let height = splitted.next().expect("Merkle tree height invalid");
        let winternitz_parameter = splitted.next().expect("Winternitz parameter invalid");

        let height: u8 = height.parse().expect("Merkle tree height invalid");
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

        let hss_parameters = HssParameter::new(lm_ots, lms);
        vec_hss_params.push(hss_parameters);
    }

    let mut splitted = ssts_params.split('/');
    let si_idx = splitted.next().expect("Signing instance index invalid");
    let si_idx: u8 = si_idx.parse().expect("Signing instance index invalid");
    let total_num_si = splitted.next().expect("Total number of signing instances invalid");
    let total_num_si: u8 = total_num_si.parse().expect("Total number of signing instances invalid");

    let top_div_height = (total_num_si as f32).log2();
    if top_div_height.fract() != 0.0 {
        panic!("Provided number of signing instances is not a power of 2");
    }
    let top_div_height = top_div_height as u8;

    // @TODO how do I know whether this "vec_hss_params" is a move, and if not, how to achieve (avoid implicit "Copy")?
    // ArrayVec implements trait "Clone", but I'm not sure about "Copy" (implicit)
    let param = SstsParameter::new(vec_hss_params, top_div_height, si_idx);
    // this here shouldn't be possible in case of "move", because then we don't have ownership anymore:
    //let vec_hss_param_test: HssParameter<Sha256_256> = HssParameter::new(LmotsAlgorithm::LmotsW1, LmsAlgorithm::LmsH5);
    //vec_hss_params.push(vec_hss_param_test);

    // same here: move or copy?
    GenKeyParameter::new(param, aux_data_size)
}

fn write(filename: &str, content: &[u8]) -> Result<(), std::io::Error> {
    let mut file = File::create(filename)?;
    file.write_all(content)?;
    Ok(())
}
