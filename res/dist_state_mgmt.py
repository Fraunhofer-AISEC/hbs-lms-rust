#!/usr/bin/env python3

# TODO arguments: add seed; option for random seed?
# TODO arguments: add name for files

import sys, subprocess, shlex, math, argparse


def main():
    args = parse()
    args = vars(args)
    print("args: ", args)

    print('Executing "sst_demo" genkey1 and genkey2 with:')

    number_of_signing_entities = args["se"]
    print("Number of signing entities: ", number_of_signing_entities)

    hss_params = args["hss"]
    print("HSS parameter: ", hss_params)

    auxsize = args["auxsize"]
    print("AUX data size: ", auxsize)

    genkey1(number_of_signing_entities, hss_params, auxsize)

    genkey2(number_of_signing_entities)

    # remove files with intermediate node hash values
    for signing_entity in range(1, number_of_signing_entities + 1):
        cmd = f"rm node_si.{signing_entity}.bin"
        result = subprocess.run(
            shlex.split(cmd), shell=False, capture_output=True, text=True
        )
        # print(result.stdout)
        # print(result.stderr)


def parse():
    parser = argparse.ArgumentParser(
        prog="dist_state_mgmt",
        description="Calls demo application to generate keys for several signing entities.",
    )

    parser.add_argument(
        "--se", dest="se", type=int, help="number of signing entities (power of 2)"
    )
    parser.add_argument(
        "--hss",
        dest="hss",
        help="HSS parameters; e.g. 10/2,15/4 [LMS-height/Winternitz-param.]",
    )
    parser.add_argument(
        "--auxsize",
        dest="auxsize",
        nargs="?",
        default="0",
        help="Max AUX data file, size in bytes",
    )

    args = parser.parse_args()

    return args


def genkey1(number_of_signing_entities, hss_params, auxsize):
    seed = "0123456701234567012345670123456701234567012345670123456701234567"
    # 1. Create private key and intermediate node value
    # hss params e.g. "10/2,15/4"
    # ssts params  e.g. "ssts=5/8" -> instance 5 of 8

    for signing_entity in range(1, number_of_signing_entities + 1):
        cmd = (
            f"cargo run --release --example sst_demo -- genkey1 mykey {hss_params} "
            f"--ssts={signing_entity}/{number_of_signing_entities} --auxsize={auxsize} --seed={seed}"
        )
        result = subprocess.run(
            shlex.split(cmd), shell=False, capture_output=True, text=True
        )
        seed = rotate(seed, 3)
        print(result.stdout)
        print(result.stderr)


def genkey2(number_of_signing_entities):
    # 2. read other intermediate node values and create public key

    for signing_entity in range(1, number_of_signing_entities + 1):
        cmd = (
            f"cargo run --release --example sst_demo -- genkey2 mykey {signing_entity}"
        )
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
