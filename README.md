# Leighton-Micali Hash-Based Signatures

[![crate][crate-image]][crate-link]
[![Docs][docs-image]][docs-link]
![Apache2/MIT licensed][license-image]
![Rust Version][rustc-image]
[![Build Status][build-image]][build-link]

LMS implementation in Rust according to the [IETF RFC 8554](https://datatracker.ietf.org/doc/html/rfc8554).
This implementation is binary compatible with the reference implementation found here: [hash-sigs](https://github.com/cisco/hash-sigs).

This crate does not require the standard library (i.e. no_std capable) and can be easily used for bare-metal programming.

## Demo
A demo application is located in the `examples` folder to demonstrate the use of the library.
This demo application can be used in the console as follows:

```
# Key generation: prepare
# Generates intermediate node, generates or reads the tree identifier (init_tree_ident 1/0), and uses "mykey" as filename base.
# One dedicated signing entity has to create the common L-0 tree identifier (--init_tree_ident=1) before other signing entities
# can generate their subtrees.
#
# The following example uses two HSS levels, first with tree height = 10 / Winternitz = 8, second with 5 / 2.
# First, a signing entity (here: 1 of 8) creates the tree identifier
cargo run --release --example sst_demo -- prepare_keygen mykey 10/8,5/2 --ssts=1/8 --auxsize=2048 \
  --seed=c912a74bc8c5fc1b2a73b96e6ce1eb2317dc9aa49806b30e578436d0f659b1f5 --init_tree_ident=1
# The signing instance index is 3 of total 8, and this signing entity will use the tree identifier and use another secret seed.
# This will use "mykey.5.prv" and "mykey.5.aux" for private key and aux data, and "mykey_treeident.bin" to write the tree identifier
cargo run --release --example sst_demo -- prepare_keygen mykey 10/8,5/2 --ssts=3/8 --auxsize=2048 \
  --seed=1eb2317dc9aa49806b30e578436d0f659b1f5c912a74bc8c5fc1b2a73b96e6ce --init_tree_ident=0

# Key generation: finalize
# After all signing entities have created their intermediate node values, the public key can be generated.
# This will use mykey.5.pub to write the public key for signing entity index 3.
cargo run --release --example sst_demo -- finalize_keygen mykey 3

# Signing
# Generates `message.txt.sig` using mykey.5.prv
cargo run --release --example sst_demo -- sign mykey 5 message.txt

# Verification
# Verifies `message.txt` with `message.txt.sig` against `mykey.5.pub`
cargo run --release --example sst_demo -- verify mykey.5 message.txt
```

## Naming conventions wrt to the IETF RFC
The naming in the RFC is done by using a single character.
To allow for a better understanding of the implementation, we have decided to use more descriptive designations.
The following table shows the mapping between the RFC and the library naming including a short description.

| RFC Naming | Library Naming       | Meaning                                                   |
|------------|----------------------|-----------------------------------------------------------|
| I          | lms_tree_identifier  | 16-byte random value to identify a single LMS tree        |
| q          | lms_leaf_identifier  | 4-byte value to identify all leafs in a single LMS tree   |
| C          | signature_randomizer | 32-byte random value added to every signature             |
| Q          | message_hash         | Output of hashed message together with I, q, D_MESG and C |
| y          | signature_data       | The actual data of the signature                          |
| p          | hash_chain_count     | The number of hash chains for a certain W parameter       |
| ls         | checksum_left_shift  | How many bits the checksum is shifted into the coef-value |
| n          | hash_function_output_size | Number of bytes that the lm_ots hash functions generates         |
| m          | hash_function_output_size | Number of bytes that the lms hash functions generates         |

## Minimum Supported Rust Version
The crate in this repository supports Rust **1.57** or higher.

Minimum supported Rust version can be changed in the future, but it will be done with a minor version bump.

## Licensing
This work is licensed under terms of the Apache-2.0 license (see [LICENSE file](LICENSE)).

### Contribution
Any contribution intentionally submitted for inclusion in the work by you, as defined in the Apache-2.0 license, shall be licensed as above, without any additional terms or conditions.

[//]: # (badges)

[crate-image]: https://img.shields.io/crates/v/hbs-lms.svg
[crate-link]: https://crates.io/crates/hbs-lms
[docs-image]: https://docs.rs/hbs-lms/badge.svg
[docs-link]: https://docs.rs/hbs-lms/
[license-image]: https://img.shields.io/badge/license-Apache2.0-blue.svg
[rustc-image]: https://img.shields.io/badge/rustc-1.57+-blue.svg
[build-image]: https://github.com/Fraunhofer-AISEC/hbs-lms-rust/workflows/lms/badge.svg?branch=master
[build-link]: https://github.com/Fraunhofer-AISEC/hbs-lms-rust/actions?query=workflow%3Alms
