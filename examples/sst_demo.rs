//use hbs_lms::*;
use std::{
    //error::Error,
    //fmt,
    //fs::{read, File},
    //io::{Read, Write},
    process::exit,
};

// @TODO: try to use via "sst::""

fn main() {
    // sst
    let _key = match hbs_lms::gen_key::genkey() {
        Ok(_) => println!("sst::gen_key OK"),
        Err(error) => panic!("sst::gen_key: error {:?}", error),
    };
    
    let _signature = match hbs_lms::sign::sign() {
        Ok(_) => println!("sst::sign OK"),
        Err(error) => panic!("sst::sign {:?}", error),
    };

    if hbs_lms::verify::verify() == false {
        println!("sst::verify failed");
        exit(1);
    }
    println!("sst::verify OK");

    exit(0);    
}