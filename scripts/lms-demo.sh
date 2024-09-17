touch message.txt

random="$(dd if=/dev/urandom bs=24 count=1 status=none | hexdump -v -e '/1 "%02X"'; echo)"

# Key generation
# Generates `mykey.prv`, `mykey.pub` with merkle tree height 10 and winternitz parameter 2
cargo run --release --example lms-demo -- genkey mykey 5/4,5/4 --seed $random &&

# Signing
# Generates `message.txt.sig`
cargo run --release --example lms-demo -- sign mykey message.txt &&

# Verification
# Verifies `message.txt` with `message.txt.sig` against `mykey.pub`
cargo run --release --example lms-demo -- verify mykey message.txt &&

# # Signing (fast_verification)
# # Generates `message.txt_mut`, `message.txt_mut.sig`
# HBS_LMS_MAX_HASH_OPTIMIZATIONS=1000 HBS_LMS_THREADS=1 cargo run --release --example lms-demo \
#     --features fast_verify -- sign_mut mykey message.txt &&

# Verification
# Verifies `message.txt` with `message.txt.sig` against `mykey.pub`
cargo run --release --example lms-demo -- verify mykey message.txt
