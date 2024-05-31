#!/usr/bin/env python3

import sys, subprocess, shlex, math, argparse, os

# w/o time measurement
# demo_binary = "cargo run --release --example sst_demo -- "
# show timings
demo_binary = "time -p target/release/examples/sst_demo "


def main():
    args = parse()
    args = vars(args)

    print('Executing "sst_demo" genkey1 and genkey2 with:')

    number_of_signing_entities = args["se"]
    print("  - Number of signing entities: ", number_of_signing_entities)

    hss_params = args["hss"]
    print("  - HSS parameter: ", hss_params)

    keyname = args["keyname"]
    print("  - Keyname: ", keyname)

    auxsize = args["auxsize"]
    print("  - AUX data size: ", auxsize)

    print("")

    genkey1(number_of_signing_entities, hss_params, auxsize, keyname)

    genkey2(number_of_signing_entities, keyname)

    # remove files with intermediate node hash values
    for signing_entity in range(1, number_of_signing_entities + 1):
        cmd = f"rm node_si.{signing_entity}.bin"
        result = subprocess.run(
            shlex.split(cmd), shell=False, capture_output=True, text=True
        )


def parse():
    parser = argparse.ArgumentParser(
        prog="dist_state_mgmt",
        description="Calls demo application to generate keys for several signing entities.",
    )

    parser.add_argument(
        "--se",
        dest="se",
        type=int,
        help="number of signing entities (power of 2)",
        required=True,
    )
    parser.add_argument(
        "--keyname",
        dest="keyname",
        type=ascii,
        help="keyname for storing files",
        required=True,
    )
    parser.add_argument(
        "--hss",
        dest="hss",
        help="HSS parameters; e.g. 10/2,15/4 [LMS-height/Winternitz-param.]",
        required=True,
    )
    parser.add_argument(
        "--auxsize",
        dest="auxsize",
        nargs="?",
        default="0",
        help="Max AUX data file, size in bytes",
        required=True,
    )

    args = parser.parse_args()

    return args


def genkey1(number_of_signing_entities, hss_params, auxsize, keyname):
    # For "deterministic" results, set the seed here:
    # seed = "abcd456701234567012345670123456701234567012345670123456701234567"

    # 1. Create private key and intermediate node value
    # hss params e.g. "10/2,15/4"
    # ssts params  e.g. "ssts=5/8" -> instance 5 of 8
    init_tree_ident = True

    for signing_entity in range(1, number_of_signing_entities + 1):
        print("GenKey1 for signing entity: ", signing_entity)
        seed = os.urandom(32).hex()

        cmd = (
            f"{demo_binary} prepare_keygen {keyname} {hss_params} "
            f"--ssts={signing_entity}/{number_of_signing_entities} --auxsize={auxsize} --seed={seed}"
        )
        if True == init_tree_ident:
            cmd = f"{cmd} --init_tree_ident=1"
        else:
            cmd = f"{cmd} --init_tree_ident=0"

        result = subprocess.run(
            shlex.split(cmd), shell=False, capture_output=True, text=True
        )
        seed = rotate(seed, 3)
        init_tree_ident = False
        print(result.stdout)
        print(result.stderr)


def genkey2(number_of_signing_entities, keyname):
    # 2. read other intermediate node values and create public key

    for signing_entity in range(1, number_of_signing_entities + 1):
        cmd = f"{demo_binary} finalize_keygen {keyname} {signing_entity}"
        result = subprocess.run(
            shlex.split(cmd), shell=False, capture_output=True, text=True
        )
        print(result.stdout)
        print(result.stderr)


def rotate(input_str, d):
    # slice string in two parts for left and right
    Rfirst = input_str[0 : len(input_str) - d]
    Rsecond = input_str[len(input_str) - d :]
    return Rsecond + Rfirst


if __name__ == "__main__":
    main()
