# Leighton-Micali Hash-Based Signatures
The purpose of this project is to implement the LMS in Rust [RFC 8554](https://datatracker.ietf.org/doc/html/rfc8554).

The implementation is binary compatible with the reference implementation [hash-sigs](https://github.com/cisco/hash-sigs).

# Demo
The examples folder includes a demo application, to see how the library can be used.

* `cargo run --release --example lms-demo -- genkey mykey 10/2`
    * Key generation
    * Generates `mykey.priv`, `mykey.pub` with merkle tree height 10 and winternitz parameter 2
* `cargo run --release --example lms-demo -- sign mykey message.txt`
    * Signing
    * Generates `message.txt.sig`
* `cargo run --release --example lms-demo -- verify mykey message.txt`
    * Verification
    * Verifies `message.txt` with `message.txt.sig` against `mykey.pub`
