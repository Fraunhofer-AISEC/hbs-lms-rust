use std::{env, fs::File, io::Write, path::Path};

fn main() {
    let out_dir = env::var("OUT_DIR").expect("No out dir");
    let dest_path = Path::new(&out_dir).join("constants.rs");
    let mut f = File::create(&dest_path).expect("Could not create file");

    if cfg!(feature = "fast_verify") {
        let max_hash_optimizations = option_env!("MAX_HASH_OPTIMIZATIONS");
        let max_hash_optimizations = max_hash_optimizations
            .map_or(Ok(10_000), str::parse)
            .expect("Could not parse MAX_HASH_OPTIMIZATIONS");

        write!(
            &mut f,
            "pub const MAX_HASH_OPTIMIZATIONS: usize = {};",
            max_hash_optimizations
        )
        .expect("Could not write file");
        println!("cargo:rerun-if-env-changed=MAX_HASH_OPTIMIZATIONS");
    }
}
