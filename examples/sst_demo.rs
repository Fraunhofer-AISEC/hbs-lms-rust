use std::{
    //error::Error,
    //fmt,
    //fs::{read, File},
    //io::{Read, Write},
    process::exit,
};
use hbs_lms::*;

// @TODO: try to use via "sst::""

type Hasher = Sha256_256;

fn main() {
    let message = [32; 0]; // 32 elements init. with 0
    let _hss_key = match hbs_lms::sst::gen_hss_key() {
        Ok(_) => println!("sst::gen_key OK"),
        Err(error) => panic!("sst::gen_key: error {:?}", error),
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

    exit(0);    
}