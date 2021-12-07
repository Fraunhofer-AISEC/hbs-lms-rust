use std::{env, fs::File, io::Write, path::Path};

fn main() {
    let out_dir = env::var("OUT_DIR").expect("No out dir");
    let dest_path = Path::new(&out_dir).join("constants.rs");
    let mut f = File::create(&dest_path).expect("Could not create file");

    let max_hash_optimizations = option_env!("HBS_LMS_MAX_HASH_OPTIMIZATIONS");
    let max_hash_optimizations: usize = max_hash_optimizations
        .map_or(Ok(10_000), str::parse)
        .expect("Could not parse HBS_LMS_MAX_HASH_OPTIMIZATIONS");
    writeln!(
        &mut f,
        "pub const MAX_HASH_OPTIMIZATIONS: usize = {};\n",
        max_hash_optimizations
    )
    .expect("Could not write file");
    println!("cargo:rerun-if-env-changed=HBS_LMS_MAX_HASH_OPTIMIZATIONS");

    let threads = option_env!("HBS_LMS_THREADS");
    let threads = threads
        .map_or(Ok(1), str::parse)
        .expect("Could not parse HBS_LMS_THREADS");
    writeln!(&mut f, "pub const THREADS: usize = {};\n", threads).expect("Could not write file");
    println!("cargo:rerun-if-env-changed=HBS_LMS_THREADS");

    let max_allowed_hss_levels = option_env!("HBS_LMS_MAX_ALLOWED_HSS_LEVELS");
    let max_allowed_hss_levels = max_allowed_hss_levels
        .map_or(Ok(8), str::parse::<usize>)
        .expect("Could not parse HBS_LMS_MAX_ALLOWED_HSS_LEVELS");
    if max_allowed_hss_levels > 8 {
        panic!("MAX_ALLOWED_HSS_LEVELS has a maximum value of 8!")
    }
    writeln!(
        &mut f,
        "pub const MAX_ALLOWED_HSS_LEVELS: usize = {};\n",
        max_allowed_hss_levels
    )
    .expect("Could not write file");
    println!("cargo:rerun-if-env-changed=HBS_LMS_MAX_ALLOWED_HSS_LEVELS");

    let tree_heights = option_env!("HBS_LMS_TREE_HEIGHTS");
    let tree_heights: Vec<_> = tree_heights
        .unwrap_or("25, 25, 25, 25, 25, 25, 25, 25")
        .split(", ")
        .collect::<Vec<_>>()
        .iter()
        .map(|&e| e.parse::<u32>().unwrap())
        .collect::<Vec<_>>();
    if tree_heights.len() != max_allowed_hss_levels {
        panic!("HBS_LMS_TREE_HEIGHTS length does not match MAX_ALLOWED_HSS_LEVELS!")
    }
    writeln!(
        &mut f,
        "pub const MAX_TREE_HEIGHT: usize = {};\n",
        tree_heights.iter().min().unwrap(),
    )
    .expect("Could not write file");
    writeln!(
        &mut f,
        "pub const TREE_HEIGHTS: [usize; {}] = {:?};\n",
        max_allowed_hss_levels, tree_heights,
    )
    .expect("Could not write file");
    println!("cargo:rerun-if-env-changed=HBS_LMS_TREE_HEIGHTS");

    let winternitz_parameters = option_env!("HBS_LMS_WINTERNITZ_PARAMETERS");
    let winternitz_parameters: Vec<_> = winternitz_parameters
        .unwrap_or("1, 1, 1, 1, 1, 1, 1, 1")
        .split(", ")
        .collect::<Vec<_>>()
        .iter()
        .map(|&e| e.parse::<u32>().unwrap())
        .collect::<Vec<_>>();
    if winternitz_parameters.len() != max_allowed_hss_levels {
        panic!("HBS_LMS_WINTERNITZ_PARAMETERS length does not match MAX_ALLOWED_HSS_LEVELS!")
    }
    writeln!(
        &mut f,
        "pub const MIN_WINTERNITZ_PARAMETER: usize = {};\n",
        winternitz_parameters.iter().min().unwrap(),
    )
    .expect("Could not write file");
    writeln!(
        &mut f,
        "pub const WINTERNITZ_PARAMETERS: [usize; {}] = {:?};\n",
        max_allowed_hss_levels, winternitz_parameters,
    )
    .expect("Could not write file");
    println!("cargo:rerun-if-env-changed=HBS_LMS_WINTERNITZ_PARAMETERS");
}
