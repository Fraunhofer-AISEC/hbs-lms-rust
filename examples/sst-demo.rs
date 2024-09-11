use clap::{Arg, ArgAction, ArgMatches, Command};
use hbs_lms::*;
use std::{
    convert::TryFrom,
    convert::TryInto,
    error::Error,
    fmt,
    fs::{read, File, OpenOptions},
    io::{Read, Write},
    process::exit,
};
use tinyvec::ArrayVec;

const GENKEY1_COMMAND: &str = "prepare_keygen";
const GENKEY2_COMMAND: &str = "finalize_keygen";
const VERIFY_COMMAND: &str = "verify";
const SIGN_COMMAND: &str = "sign";

const ARG_KEYNAME: &str = "keyname";
const ARG_MESSAGE: &str = "file";
const ARG_HSS_PARAMETER: &str = "hss";
const ARG_SIGN_ENTITY_IDX: &str = "se_param";
const ARG_SEED: &str = "seed";
const ARG_AUXSIZE: &str = "auxsize";
const ARG_INIT_TREE_IDENT: &str = "init_tree_ident";
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

type Hasher = Sha256_192;

struct GenKeyParameter {
    hss_parameters: ArrayVec<[HssParameter<Hasher>; hbs_lms::REF_IMPL_MAX_ALLOWED_HSS_LEVELS]>,
    sst_extension: SstExtension,
    aux_data: usize,
}

impl GenKeyParameter {
    pub fn new(
        hss_parameters: ArrayVec<[HssParameter<Hasher>; hbs_lms::REF_IMPL_MAX_ALLOWED_HSS_LEVELS]>,
        sst_extension: SstExtension,
        aux_data: Option<usize>,
    ) -> Self {
        let aux_data = aux_data.unwrap_or(AUX_DATA_DEFAULT_SIZE);
        Self {
            hss_parameters,
            sst_extension,
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
            .arg(Arg::new(ARG_SSTS_PARAM).long(ARG_SSTS_PARAM).required(true).takes_value(true).value_name(ARG_SSTS_PARAM)
                .help(
                "Specify SSTS parameters (e.g. --ssts=3/8 => signing entity 3 of total 8"))
            .arg(Arg::new(ARG_INIT_TREE_IDENT).long(ARG_INIT_TREE_IDENT).action(ArgAction::SetTrue).help("Announce initialization of tree identifier"))
            .arg(Arg::new(ARG_AUXSIZE).long(ARG_AUXSIZE).required(false).takes_value(true).value_name(ARG_AUXSIZE).help(
                "Specify AUX data size in bytes"))
            .arg(Arg::new(ARG_SEED).long(ARG_SEED).required(true).takes_value(true).value_name(ARG_SEED)),
    )
    .subcommand(
        Command::new(GENKEY2_COMMAND)
        .arg(Arg::new(ARG_KEYNAME).required(true))
        .arg(Arg::new(ARG_SIGN_ENTITY_IDX).required(true).help(
            "Specify signing entity index (1..n))"))
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

    let matches = command.get_matches();

    if let Some(args) = matches.subcommand_matches(GENKEY1_COMMAND) {
        prepare_keygen(args)?;
        println!(
            "Single-subtree-structure: intermediate node and private key successfully generated!"
        );
        return Ok(());
    }

    if let Some(args) = matches.subcommand_matches(GENKEY2_COMMAND) {
        finalize_keygen(args)?;
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
            return Ok(());
        } else {
            println!("Verification failed!");
            exit(-1);
        }
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
    let mut aux_data = read(&aux_data_filename)
        .unwrap_or_else(|_| panic!("{} file cannot be read", &aux_data_filename));

    let tree_ident_filedata = read_file(&format!("{}_treeident.bin", keyname));
    let tree_identifier: LmsTreeIdentifier = tree_ident_filedata
        .try_into()
        .unwrap_or_else(|_| panic!("Tree identifier has wrong length"));

    let mut private_key_update_function =
        |new_key: &[u8]| write(&private_key_filename, new_key).map_err(|_| ());

    let signature = hbs_lms::sign::<Hasher>(
        &message_data,
        &private_key_data,
        &mut private_key_update_function,
        Some(&mut &mut aux_data[..]),
        Some(&tree_identifier),
    )
    .unwrap_or_else(|_| panic!("Signing failed"));

    write(&signature_filename, signature.as_ref())
}

fn verify(args: &ArgMatches) -> bool {
    let keyname: String = get_parameter(ARG_KEYNAME, args);
    let message_name: String = get_parameter(ARG_MESSAGE, args);

    let public_key_name = get_public_key_filename(&keyname, None);
    let signature_name = get_signature_filename(&message_name);

    let signature_data = read_file(&signature_name);
    let message_data = read_file(&message_name);
    let public_key_data = read_file(&public_key_name);

    hbs_lms::verify::<Hasher>(&message_data, &signature_data, &public_key_data).is_ok()
}

fn get_filename(filename: &str, idx: Option<u8>, suffix: &str) -> String {
    idx.map_or(format!("{}{}", filename, suffix), |idx| {
        format!("{}.{}{}", filename, &idx, suffix)
    })
}

fn get_public_key_filename(keyname: &str, idx: Option<u8>) -> String {
    get_filename(keyname, idx, ".pub")
}

fn get_signature_filename(message_name: &str) -> String {
    get_filename(message_name, None, ".sig")
}

fn get_private_key_filename(private_key: &str, idx: Option<u8>) -> String {
    get_filename(private_key, idx, ".prv")
}

fn get_aux_filename(keyname: &str, idx: Option<u8>) -> String {
    get_filename(keyname, idx, ".aux")
}

fn get_treeident_filename(keyname: &str, idx: Option<u8>) -> String {
    get_filename(keyname, idx, "_treeident.bin")
}

fn get_parameter(name: &str, args: &ArgMatches) -> String {
    args.value_of(name)
        .expect("Parameter must be present.")
        .into()
}

fn read_file(file_name: &str) -> Vec<u8> {
    let mut data: Vec<u8> = Vec::new();
    std::fs::File::open(file_name)
        .unwrap_or_else(|_| panic!("{} file could not be opened", file_name))
        .read_to_end(&mut data)
        .unwrap_or_else(|_| panic!("{} file could not be read", file_name));
    data
}

fn prepare_keygen(args: &ArgMatches) -> Result<(), Box<dyn std::error::Error>> {
    let keyname: String = get_parameter(ARG_KEYNAME, args);

    let arg_init_tree_ident = args.get_flag(ARG_INIT_TREE_IDENT);
    let treeident_filename = get_treeident_filename(&keyname, None);
    let mut tree_identifier = if !arg_init_tree_ident {
        read_file(&treeident_filename)
            .try_into()
            .unwrap_or_else(|_| panic!("Tree identifier has wrong length"))
    } else {
        LmsTreeIdentifier::default()
    };

    let genkey_parameter = parse_genkey1_parameter(
        &get_parameter(ARG_HSS_PARAMETER, args),
        &get_parameter(ARG_SSTS_PARAM, args),
        &get_parameter(ARG_AUXSIZE, args),
    );
    let sst_extension = genkey_parameter.sst_extension;

    let encoded_seed = args
        .value_of(ARG_SEED)
        .ok_or(DemoError("No seed given".to_string()))?;
    let decoded_seed = hex::decode(encoded_seed)?;
    (decoded_seed.len() == Hasher::OUTPUT_SIZE.into())
        .then_some(())
        .ok_or(DemoError(format!(
            "Seed length is {} bytes, but length of {} bytes is expected",
            decoded_seed.len(),
            Hasher::OUTPUT_SIZE
        )))?;
    let mut seed = Seed::<Hasher>::default();
    seed.as_mut_slice().copy_from_slice(&decoded_seed[..]);

    let mut aux_data = vec![0u8; genkey_parameter.aux_data];
    let aux_slice: &mut &mut [u8] = &mut &mut aux_data[..];

    // create our private key
    let (signing_key, intermed_node_hashval) = prepare_sst_keygen(
        &genkey_parameter.hss_parameters,
        &sst_extension,
        &seed,
        Some(aux_slice),
        &mut tree_identifier,
    )
    .unwrap_or_else(|_| panic!("Could not generate keys"));

    let private_key_filename =
        get_private_key_filename(&keyname, Some(sst_extension.signing_entity_idx()));
    write(private_key_filename.as_str(), signing_key.as_slice())?;

    // write own node value and signing entity to file
    let interm_node_filename = format!("node_si.{}.bin", sst_extension.signing_entity_idx());

    // if file exists, overwrite
    write(
        interm_node_filename.as_str(),
        &sst_extension.signing_entity_idx().to_be_bytes(),
    )?;
    // and append
    let mut intermed_node_file = OpenOptions::new()
        .create(true)
        .append(true)
        .open(interm_node_filename.as_str())
        .unwrap();
    intermed_node_file.write_all(intermed_node_hashval.as_slice())?;

    let aux_filename: String = get_aux_filename(&keyname, Some(sst_extension.signing_entity_idx()));
    write(&aux_filename, aux_slice)?;

    Ok(write(&treeident_filename, &tree_identifier)?)
}

fn finalize_keygen(args: &ArgMatches) -> Result<(), Box<dyn std::error::Error>> {
    // get signing entity number and name of private keyfile from args
    let keyname: String = get_parameter(ARG_KEYNAME, args);
    let signing_entity: u8 = get_parameter(ARG_SIGN_ENTITY_IDX, args)
        .parse::<u8>()
        .unwrap();

    // AUX data: created in genkey1, here we read the file
    let aux_filename: String = get_aux_filename(&keyname, Some(signing_entity));
    let mut aux_data_v: Vec<u8> = read_file(&aux_filename);
    let aux_slice: &mut &mut [u8] = &mut &mut aux_data_v[..];

    // read private key
    let private_key_name = get_private_key_filename(&keyname, Some(signing_entity));
    let private_key_data = read_file(&private_key_name);

    // here we need one additional API call to know which files we have to read dep. on HSS config.
    let num_signing_entities = get_num_signing_entities::<Hasher>(&private_key_data)
        .unwrap_or_else(|_| panic!("genkey step 2: invalid config"));

    // read intermediate node values from files (ours and others) and pass for calc.

    let mut node_array =
        ArrayVec::<[ArrayVec<[u8; MAX_HASH_SIZE]>; MAX_SSTS_SIGNING_ENTITIES]>::new();

    for idx in 1..=num_signing_entities {
        let file_data: Vec<u8> = read_file(&format!("node_si.{idx}.bin"));
        (file_data.len() == (1 + Hasher::OUTPUT_SIZE as usize))
            .then_some(())
            .unwrap_or_else(|| {
                panic!(
                    "genkey2(): intermediate node file size is {}, should be {}",
                    file_data.len(),
                    (1 + MAX_HASH_SIZE)
                )
            });
        let node = ArrayVec::<[u8; MAX_HASH_SIZE]>::try_from(&file_data[1..]).unwrap();
        node_array.push(node);
    }

    let treeident_filename = get_treeident_filename(&keyname, None);
    let tree_ident_filedata = read_file(&treeident_filename);
    let tree_identifier: LmsTreeIdentifier = tree_ident_filedata
        .try_into()
        .unwrap_or_else(|_| panic!("Tree identifier has wrong length"));
    let treeident_filename = get_treeident_filename(&keyname, Some(signing_entity));
    write(&treeident_filename, &tree_identifier)
        .unwrap_or_else(|_| panic!("Could not write key tree identifier"));

    let verifying_key = finalize_sst_keygen::<Hasher>(
        &private_key_data,
        &node_array,
        Some(aux_slice),
        &tree_identifier,
    )
    .unwrap_or_else(|_| panic!("Could not generate verifying key"));

    write(&aux_filename, aux_slice)?;

    let public_key_filename = get_public_key_filename(&keyname, Some(signing_entity));
    Ok(write(&public_key_filename, verifying_key.as_slice())?)
}

fn parse_genkey1_parameter(hss_params: &str, ssts_params: &str, auxsize: &str) -> GenKeyParameter {
    let mut vec_hss_params: ArrayVec<[_; hbs_lms::REF_IMPL_MAX_ALLOWED_HSS_LEVELS]> =
        Default::default();

    let auxsize: usize = auxsize.parse().expect("Could not parse aux data size");
    let aux_data_size = (auxsize != 0).then_some(auxsize);

    for hss_param in hss_params.split(',') {
        let mut splitted = hss_param.split('/');
        let height: u8 = splitted
            .next()
            .expect("Splitted does not contain height")
            .parse::<u8>()
            .expect("Parsing of height failed");
        let winternitz_parameter: u8 = splitted
            .next()
            .expect("Splitted does not contain winternitz_parameter")
            .parse::<u8>()
            .expect("Parsing of winternitz_parameter failed");

        let lms = match height {
            5 => LmsAlgorithm::LmsH5,
            10 => LmsAlgorithm::LmsH10,
            15 => LmsAlgorithm::LmsH15,
            20 => LmsAlgorithm::LmsH20,
            25 => LmsAlgorithm::LmsH25,
            _ => panic!("Height not supported"),
        };
        let lm_ots = match winternitz_parameter {
            1 => LmotsAlgorithm::LmotsW1,
            2 => LmotsAlgorithm::LmotsW2,
            4 => LmotsAlgorithm::LmotsW4,
            8 => LmotsAlgorithm::LmotsW8,
            _ => panic!("Wrong winternitz parameter"),
        };

        vec_hss_params.push(HssParameter::new(lm_ots, lms));
    }

    let mut splitted = ssts_params.split('/');
    let si_idx: u8 = splitted
        .next()
        .expect("Splitted does not contain si_idx")
        .parse::<u8>()
        .expect("Parsing of si_idx failed");
    let total_num_si: u8 = splitted
        .next()
        .expect("Splitted does not contain total_num_si")
        .parse::<u8>()
        .expect("Parsing of total_num_si failed");

    let l0_top_div = ((total_num_si as f32).log2().fract() == 0.0)
        .then_some((total_num_si as f32).log2() as u8)
        .unwrap();

    let sst_extension = SstExtension::new(si_idx, l0_top_div).unwrap();

    GenKeyParameter::new(vec_hss_params, sst_extension, aux_data_size)
}

fn write(filename: &str, content: &[u8]) -> Result<(), std::io::Error> {
    let mut file = File::create(filename)?;
    file.write_all(content)
}
