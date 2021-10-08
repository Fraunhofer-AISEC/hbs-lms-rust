.phony: all test

all:
	cargo fmt
	cargo build
	cargo clippy
	cargo build --examples

test:
	cargo test

clean:
	cargo clean

riscv:
	cargo build --target riscv32imac-unknown-none-elf

check-for-todos:
	@git grep -n -i -e todo -e fixme -- \
	    :^Makefile \
	    :^.gitlab-ci.yml \
	    2>&1 | tee check_for_todos_results.txt

	@if [ ! -s check_for_todos_results.txt ]; then \
	    echo "Success: No TODO comments found."; \
	else \
	    echo "Failure: Found TODO comments"; \
	    exit 1; \
	fi
