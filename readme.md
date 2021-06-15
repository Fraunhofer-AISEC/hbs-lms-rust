# Leighton-Micali Hash-Based Signatures
The purpose of this project is to implement the LMS in Rust [RFC 8554](https://datatracker.ietf.org/doc/html/rfc8554).

The implementation is binary compatible (except the private key) with the reference implementation [hash-sigs](https://github.com/cisco/hash-sigs).

# Status
The reference implementation always generates HSS signatures, even when only one tree is used. The current implementation doesn't support HSS yet. But to be binary compatible, we can read and write signatures with HSS Level = 1.

# Demo
The examples folder includes a demo application, to see how the library can be used.

* `cargo run --release --example demo -- genkey mykey 10/2`
    * Key generation
    * Generates `mykey.priv`, `mykey.pub` with merkle tree height 10 and winternitz parameter 2
* `cargo run --release --example demo -- sign mykey message.txt`
    * Signing
    * Generates `message.txt.sig`
* `cargo run --release --example demo -- verify mykey message.txt`
    * Verification
    * Verifies `message.txt` with `message.txt.sig` against `mykey.pub`