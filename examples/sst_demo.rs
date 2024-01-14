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

const GENSUBTREE_COMMAND: &str = "gensubtree";
const GENPUBKEY_COMMAND: &str = "genpubkey";
const VERIFY_COMMAND: &str = "verify";
const SIGN_COMMAND: &str = "sign";

#[cfg(feature = "fast_verify")]
const SIGN_MUT_COMMAND: &str = "sign_mut";

const ARG_KEYNAME: &str = "keyname";
const ARG_MESSAGE: &str = "file";
const ARG_SSTS_PARAMETER: &str = "parameter";
const ARG_SI_PARAMETER: &str = "si_param";
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
    ssts_param: SstsParameter<Hasher>,
    _aux_data: usize,
}

impl GenKeyParameter {
    pub fn new(ssts_param: SstsParameter<Hasher>, aux_data: Option<usize>) -> Self {
        let _aux_data = aux_data.unwrap_or(AUX_DATA_DEFAULT_SIZE);
        Self {
            ssts_param,
            _aux_data,
        }
    }
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    /*
    let message = [32; 0]; // 32 elements init. with 0

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
     */

    // ********** code from "lms-demo.rs" to steal/import parameter parsing etc. **********
    let command = Command::new("SSTS Demo")
    .about("Generates SSTS keys and uses them for signing and verifying.")
    .subcommand(
        Command::new(GENSUBTREE_COMMAND)
            .arg(Arg::new(ARG_KEYNAME).required(true))
            .arg(Arg::new(ARG_SSTS_PARAMETER).required(true).help(
                "Specify LMS parameters (e.g. 5/4/2/1 (tree height = 5, Winternitz parameter = 4, top height = 2, signing entity = 1))"))
            .arg(Arg::new(ARG_SEED).long(ARG_SEED).required(true).takes_value(true).value_name("seed")),
    )
    .subcommand(
        Command::new(GENPUBKEY_COMMAND)
        .arg(Arg::new(ARG_KEYNAME).required(true))
        .arg(Arg::new(ARG_SI_PARAMETER).required(true).help(
            "Specify signing instance number (1..n))"))
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

    if let Some(args) = matches.subcommand_matches(GENSUBTREE_COMMAND) {
        gen_key_subtree(args)?;
        println!(
            "Single-subtree-structure: intermediate node and private key successfully generated!"
        );
        return Ok(());
    }

    if let Some(args) = matches.subcommand_matches(GENPUBKEY_COMMAND) {
        gen_key_ssts(args)?;
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

    // TODO signing entity idx
    let private_key_name = get_private_key_filename(&keyname, 1);
    let signature_name = get_signature_filename(&message_name);

    let private_key_data = read_file(&private_key_name);
    let message_data = read_file(&message_name);

    // TODO signing entity idx
    let aux_data_name = get_aux_filename(&keyname, 1);
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
    let public_key_name = get_public_key_filename(&keyname, 1);
    let signature_name = get_signature_filename(&message_name);

    let signature_data = read_file(&signature_name);
    let message_data = read_file(&message_name);
    let public_key_data = read_file(&public_key_name);

    hbs_lms::verify::<Hasher>(&message_data, &signature_data, &public_key_data).is_ok()
}

fn get_public_key_filename(keyname: &str, idx: u8) -> String {
    keyname.to_string() + &idx.to_string() + ".pub"
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

fn get_private_key_filename(private_key: &str, idx: u8) -> String {
    private_key.to_string() + &idx.to_string() + "." + ".prv"
}

fn get_aux_filename(keyname: &str, idx: u8) -> String {
    keyname.to_string() + &idx.to_string() + ".aux"
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

fn gen_key_subtree(args: &ArgMatches) -> Result<(), Box<dyn std::error::Error>> {
    let keyname: String = get_parameter(ARG_KEYNAME, args);

    let genkey_parameter = parse_genkey1_parameter(&get_parameter(ARG_SSTS_PARAMETER, args));
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

    // TODO should we generate aux data here or in next step -- or in both?

    // create our private key
    let (signing_key, node_pubkey) =
        gen_sst_subtree(&ssts_param, &seed).unwrap_or_else(|_| panic!("Could not generate keys"));

    //println!("sst_demo::gen_key_subtree(): node value: {:?}", node_pubkey);
    let private_key_filename = get_private_key_filename(&keyname, ssts_param.get_entity_idx());
    write(private_key_filename.as_str(), signing_key.as_slice())?;

    // write own node value and signing instance to file
    // TODO     maybe also HSS/LMS/LM-OTS parameters, to ensure that we got the same parameters among all signing instances
    let interm_node_filename = String::from("node_si")
        + &(ssts_param.get_entity_idx().to_string())
        + &String::from(".bin"); // TODO into function

    // if file exists, overwrite
    write(
        interm_node_filename.as_str(),
        &ssts_param.get_entity_idx().to_be_bytes(),
    )?;
    // and append
    let mut interm_node_file = OpenOptions::new()
        .create(true)
        .write(true)
        .append(true)
        .open(interm_node_filename.as_str())
        .unwrap();
    interm_node_file.write_all(node_pubkey.as_slice())?;

    Ok(())
}

fn gen_key_ssts(args: &ArgMatches) -> Result<(), Box<dyn std::error::Error>> {
    // get signing instance number and name of private keyfile from args
    let keyname: String = get_parameter(ARG_KEYNAME, args);
    let signing_instance: String = get_parameter(ARG_SI_PARAMETER, args);

    println!("keyname: {} -- SI: {}", keyname, signing_instance);

    // read private key
    let private_key_name =
        get_private_key_filename(&keyname, signing_instance.parse::<u8>().unwrap());
    let private_key_data = read_file(&private_key_name);

    // (here so far we only had the structs "SigningKey" and "VerifyingKey" -> leave it at that if possible)
    // read HSS configuration from key -> how many SI and LMS config (tree height...)

    let (ssts_param, lms_tree_ident) = get_config::<Hasher>(&private_key_data)
        .unwrap_or_else(|_| panic!("genkey step 2: invalid config"));

    println!("lms_tree_ident: {:?}", lms_tree_ident);

    // TODO maybe compare with HSS configuration in the "node files"
    // read intermediate node values from files (ours and others) and pass for calc.
    let num_signing_entities = 2u32.pow(ssts_param.get_top_height() as u32);
    //let mut vec_intermed_nodes = Vec::new();
    let mut node_array: ArrayVec<[ArrayVec<[u8; MAX_HASH_SIZE]>; MAX_DSM_SIGNING_ENTITIES]> =
        Default::default();

    for idx in 1..=num_signing_entities {
        let interm_node_filename =
            String::from("node_si") + &(idx.to_string()) + &String::from(".bin"); // TODO into function

        //println!("read intermediate node value for signing entity num {}", idx);
        let file_data: Vec<u8> = read_file(&interm_node_filename);
        if file_data.len() != (1 + MAX_HASH_SIZE) {
            panic!(
                "genkey step 2: file data len is {}, should be {}",
                file_data.len(),
                (1 + MAX_HASH_SIZE)
            );
        }

        // let mut node: ArrayVec<[u8; MAX_HASH_SIZE]> = Default::default();
        // node.push(file_data[1..]); // TODO easier?
        // TODO that works but is probably a really bad solution

        let mut node: [u8; MAX_HASH_SIZE] = [0; MAX_HASH_SIZE];
        node.copy_from_slice(&file_data[1..]); // TODO easier?
        node_array.push(node.into());
        //node_array[(idx-1) as usize].extend(&file_data[1..]);
    }

    let _pubkey = gen_pub_key::<Hasher>(&node_array, ssts_param.get_top_height(), lms_tree_ident);
    println!("pub key (node 1) hash value: {:?}", _pubkey);

    // VerifyingKey ?
    //let intermediate_nodes = ArrayVec<Nod

    // create public key (VerifyingKey) and write to file

    //let public_key_filename = get_public_key_name(&keyname);

    let aux_data_name = get_aux_filename(&keyname, signing_instance.parse::<u8>().unwrap());
    let mut _aux_data = read(aux_data_name).ok();
    //let aux_slice: &mut &mut [u8] = &mut &mut aux_data[..];

    // retrieve PrivateKey private_key: &ReferenceImplPrivateKey<H>
    //gen_sst_pubkey(&private_key_data, Some(aux_slice));

    //write(public_key_filename.as_str(), verifying_key.as_slice())?;

    Ok(())
}

fn parse_genkey1_parameter(parameter: &str) -> GenKeyParameter {
    let mut vec_hss_params: ArrayVec<[_; hbs_lms::REF_IMPL_MAX_ALLOWED_HSS_LEVELS]> =
        Default::default();

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
    let mut entity_idx: u8 = 0;
    let mut top_part_height: u8 = 0;
    let mut is_first_loop = true;

    for parameter in parameters {
        let mut splitted = parameter.split('/');

        let height = splitted.next().expect("Merkle tree height invalid");
        let winternitz_parameter = splitted.next().expect("Winternitz parameter invalid");

        let height: u8 = height.parse().expect("Merkle tree height invalid");
        let winternitz_parameter: u8 = winternitz_parameter
            .parse()
            .expect("Winternitz parameter not correct specified");

        if true == is_first_loop {
            is_first_loop = false;
            if let Some(s_top_part_height) = splitted.next() {
                // if we have a top_part_height, we also need an entity idx
                let s_entity_idx = splitted
                    .next()
                    .expect("Top part height provided, but signing entity number missing.");
                // @TODO check: invalid if "height - top_part_height < 1"
                top_part_height = s_top_part_height.parse().expect("Top part height invalid");
                // @TODO check: invalid if ...dep. on height and top_part_height
                entity_idx = s_entity_idx.parse().expect("Signing entity index invalid");
            }
        }

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

    // @TODO how do I know whether this "vec_hss_params" is a move, and if not, how to achieve (avoid implicit "Copy")?
    // ArrayVec implements trait "Clone", but I'm not sure about "Copy" (implicit)
    let ssts_param = SstsParameter::new(vec_hss_params, top_part_height, entity_idx);
    // this here shouldn't be possible in case of "move", because then we don't have ownership anymore:
    //let vec_hss_param_test: HssParameter<Sha256_256> = HssParameter::new(LmotsAlgorithm::LmotsW1, LmsAlgorithm::LmsH5);
    //vec_hss_params.push(vec_hss_param_test);

    // same here: move or copy?
    GenKeyParameter::new(ssts_param, aux_data_size)
}

fn write(filename: &str, content: &[u8]) -> Result<(), std::io::Error> {
    let mut file = File::create(filename)?;
    file.write_all(content)?;
    Ok(())
}
