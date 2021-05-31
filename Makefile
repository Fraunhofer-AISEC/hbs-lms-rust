.phony: all test

all:
	cargo fmt
	cargo build
	cargo clippy

test:
	cargo test