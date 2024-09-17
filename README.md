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
Two demo applications are located in the `examples` folder to demonstrate the use of the library.
The examples are the [lms-demo](scripts/lms-demo.sh) and the [sst-demo](scripts/sst-demo.sh).

## Naming conventions wrt to the IETF RFC
The naming in the RFC is done by using a single character.
To allow for a better understanding of the implementation, we have decided to use more descriptive designations.
The following table shows the mapping between the RFC and the library naming including a short description.

| RFC Naming | Library Naming       | Meaning                                                   |
|------------|----------------------|-----------------------------------------------------------|
| I          | lms_tree_identifier       | 16-byte random value to identify a single LMS tree        |
| q          | lms_leaf_identifier       | 4-byte value to identify all leafs in a single LMS tree   |
| C          | signature_randomizer      | 32-byte random value added to every signature             |
| Q          | message_hash              | Output of hashed message together with I, q, D_MESG and C |
| y          | signature_data            | The actual data of the signature                          |
| p          | num_winternitz_chains     | The number of hash chains for a certain W parameter       |
| ls         | checksum_left_shift       | How many bits the checksum is shifted into the coef-value |
| n          | hash_function_output_size | Number of bytes that the lm_ots hash functions generates  |
| m          | hash_function_output_size | Number of bytes that the lms hash functions generates     |

## Minimum Supported Rust Version
The crate in this repository supports Rust **1.63** or higher.

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
[rustc-image]: https://img.shields.io/badge/rustc-1.63+-blue.svg
[build-image]: https://github.com/Fraunhofer-AISEC/hbs-lms-rust/workflows/lms/badge.svg?branch=master
[build-link]: https://github.com/Fraunhofer-AISEC/hbs-lms-rust/actions?query=workflow%3Alms
