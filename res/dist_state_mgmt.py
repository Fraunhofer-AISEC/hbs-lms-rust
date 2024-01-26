#!/usr/bin/env python3

#!/mnt/daten/dev/hbs-lms-rust-priv.git/.venv/bin/python
# TODO how to avoid an absolute path?
# TODO add several HSS parameters

import sys, subprocess, shlex, math, argparse


def parse():
  parser = argparse.ArgumentParser(
                    prog='dist_state_mgmt',
                    description='Calls demo application to generate keys for several signing entities.')

  parser.add_argument('--se', dest='se', type=int, help="number of signing entities (power of 2)") # we derive the top division from that
  parser.add_argument('--hss', dest='hss', help="HSS parameters; currently only one HSS level supported, e.g. 10/2 = LMS-height / Winternitz-param.")

  args = parser.parse_args()

  return args


def main():

  args = parse()
  args = vars(args)
  print("args: ", args)

  print("Executing \"sst_demo\" genkey1 and genkey2 with:")
  number_of_signing_entities = args['se']
  print("Number of signing entities: ", number_of_signing_entities)

  hss_params = args['hss']
  print("HSS parameter: ", hss_params)

  top_div_height = math.log(number_of_signing_entities, 2)
  if not top_div_height.is_integer():
    print("number of signing entities has to be power of 2")

  top_div_height = int(top_div_height)
  print("calc. top_div_height: ", top_div_height)


  # 1. Create private key and intermediate node value

  # cargo run --release --example sst_demo -- genkey1 mykey 10/2/5/3:100000 --seed 0123456701234567012345670123456701234567012345670123456701234567
  # currently w/o aux size
  # cargo run --release --example sst_demo -- genkey1 mykey 10/2/5/3 --seed 0123456701234567012345670123456701234567012345670123456701234567
  cmd_1 = "cargo run --release --example sst_demo -- genkey1 mykey "
  # then hss config
  cmd_3 = " --seed 0123456701234567012345670123456701234567012345670123456701234567"

  for signing_entity in range(1, number_of_signing_entities+1):
    hss_string = hss_params + "/" + str(top_div_height) + "/" + str(signing_entity)
    #hss_string = hss_params #+ "/" + str(top_div_height) + "/" + str(signing_entity)
    cmd_total = cmd_1 + hss_string + cmd_3
    print("command: ", cmd_total)
    result = subprocess.run(shlex.split(cmd_total), shell=False, capture_output=True, text=True)
    print(result.stdout)
    print(result.stderr)


  # 2. read other intermediate node values and create public key

  # cargo run --release --example sst_demo -- genkey1 mykey 1 --auxsize=10000 --seed 0123456701234567012345670123456701234567012345670123456701234567
  cmd_1 = "cargo run --release --example sst_demo -- genkey2 mykey "
  # then se (signing entity) 1..n
  cmd_3 = " --auxsize=5000"

  for signing_entity in range(1, number_of_signing_entities+1):
    cmd_total = cmd_1 + str(signing_entity) + cmd_3
    print("command: ", cmd_total)
    result = subprocess.run(shlex.split(cmd_total), shell=False, capture_output=True, text=True)
    print(result.stdout)
    print(result.stderr)





if __name__ == "__main__":
  main()
