.phony: all test

all:
	cargo build
	cargo clippy

test:
	cargo test