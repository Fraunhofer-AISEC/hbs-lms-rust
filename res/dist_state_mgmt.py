#!/usr/bin/env python3

#!/mnt/daten/dev/hbs-lms-rust-priv.git/.venv/bin/python
# TODO how to avoid an absolute path?
# TODO add several HSS parameters

import sys, subprocess, shlex, math, argparse


def main():

  args = parse()
  args = vars(args)
  print("args: ", args)

  print("Executing \"sst_demo\" genkey1 and genkey2 with:")

  number_of_signing_entities = args['se']
  print("Number of signing entities: ", number_of_signing_entities)

  hss_params = args['hss']
  print("HSS parameter: ", hss_params)

  auxsize = args['auxsize']
  print("AUX data size: ", auxsize)

  genkey1(number_of_signing_entities, hss_params, auxsize)

  genkey2(number_of_signing_entities)

  # remove files with intermediate node hash values
  for signing_entity in range(1, number_of_signing_entities+1):
    cmd = "rm node_si." + str(signing_entity) + ".bin"
    result = subprocess.run(shlex.split(cmd), shell=False, capture_output=True, text=True)
    #print(result.stdout)
    #print(result.stderr)


def parse():
  parser = argparse.ArgumentParser(
                    prog='dist_state_mgmt',
                    description='Calls demo application to generate keys for several signing entities.')

  parser.add_argument('--se', dest='se', type=int, help="number of signing entities (power of 2)")
  parser.add_argument('--hss', dest='hss', help="HSS parameters; e.g. 10/2,15/4 [LMS-height/Winternitz-param.]")
  parser.add_argument('--auxsize', dest='auxsize', nargs='?', default='0', help="AUX data size in bytes")

  args = parser.parse_args()

  return args


def genkey1(number_of_signing_entities, hss_params, auxsize):
  # 1. Create private key and intermediate node value
  cmd_1 = "cargo run --release --example sst_demo -- genkey1 mykey"
  # hss params e.g. "10/2,15/4"
  # ssts params  e.g. "ssts=5/8" -> instance 5 of 8
  cmd_3 = " --seed 0123456701234567012345670123456701234567012345670123456701234567"

  for signing_entity in range(1, number_of_signing_entities+1):
    ssts_string = "--ssts=" + str(signing_entity) + "/" + str(number_of_signing_entities)
    aux_string = "--auxsize=" + auxsize
    cmd_total = cmd_1 + " " + hss_params + " " + ssts_string + " " + aux_string + " " + cmd_3
    #print("command: ", cmd_total)
    result = subprocess.run(shlex.split(cmd_total), shell=False, capture_output=True, text=True)
    print(result.stdout)
    print(result.stderr)


def genkey2(number_of_signing_entities):
  # 2. read other intermediate node values and create public key
  cmd_1 = "cargo run --release --example sst_demo -- genkey2 mykey "

  for signing_entity in range(1, number_of_signing_entities+1):
    cmd_total = cmd_1 + str(signing_entity)
    #print("command: ", cmd_total)
    result = subprocess.run(shlex.split(cmd_total), shell=False, capture_output=True, text=True)
    print(result.stdout)
    print(result.stderr)


if __name__ == "__main__":
  main()
