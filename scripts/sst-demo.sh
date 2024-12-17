MAX_SE_IDX=8

touch message.txt

random="$(dd if=/dev/urandom bs=24 count=1 status=none | hexdump -v -e '/1 "%02X"'; echo)"

# Key generation: prepare
# Generates intermediate node, generates or reads the tree identifier (init_tree_ident 1/0), and uses "mykey" as filename base.
# One dedicated signing entity has to create the common L-0 tree identifier (--init_tree_ident=1) before other signing entities
# can generate their subtrees.
#
# The following example uses two HSS levels, first with tree height = 10 / Winternitz = 8, second with 5 / 2.
# First, a signing entity (here: 1 of 8) creates the tree identifier
cargo run --release --example sst-demo -- prepare_keygen mykey 10/4 --ssts=1/$MAX_SE_IDX \
    --auxsize=2048 --seed $random --init_tree_ident

for se_idx in $(seq 2 $MAX_SE_IDX);
do
    random="$(dd if=/dev/urandom bs=24 count=1 status=none | hexdump -v -e '/1 "%02X"'; echo)"

    # Create signing entities with index 2 to 8, will use same tree identifier but another secret seed.
    # This will use "mykey.X.prv" and "mykey.X.aux" for private key and aux data, and "mykey.X_treeident.bin" to write the tree identifier
    cargo run --release --example sst-demo -- prepare_keygen mykey 10/4 --ssts=$se_idx/$MAX_SE_IDX \
        --auxsize=2048 --seed $random
done

# Key generation: finalize
# After all signing entities have created their intermediate node values, the public key can be generated.
# This will use mykey.5.pub to write the public key for signing entity index 5.
cargo run --release --example sst-demo -- finalize_keygen mykey 5 &&

# Signing
# Generates `message.txt.sig` using mykey.5.prv
cargo run --release --example sst-demo -- sign mykey.5 message.txt &&

# Verification
# Verifies `message.txt` with `message.txt.sig` against `mykey.5.pub`
cargo run --release --example sst-demo -- verify mykey.5 message.txt &&
cargo run --release --example lms-demo -- verify mykey.5 message.txt
