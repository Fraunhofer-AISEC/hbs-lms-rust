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

# Naming conventions
| RFC Naming | Library Naming       | Meaning                                                   |
|------------|----------------------|-----------------------------------------------------------|
| I          | lms_tree_identifier  | 16-byte random value to identify a single LMS tree        |
| q          | lms_leaf_identifier  | 4-byte value to identify all leafs in a single LMS tree   |
| C          | signature_randomizer | 32-byte random value added to every signature             |
| Q          | message_hash         | Output of hashed message together with I, q, D_MESG and C |
| y          | signature_data       | The actual data of the signature                          |