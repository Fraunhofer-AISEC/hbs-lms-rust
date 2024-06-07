Cross build for nrf52840 / ARM
==============================

This folder contains some configuration files for cross building.

# Problem

I could not figure out how to combine the different configurations for x86 and ARM builds in one `.cargo/Cargo.toml` and one `.cargo/config.toml`.
In particular, the `dev-dependencies` for x86 tests and benches seemed to cause issues, becasue they use `std` which can't be used for the cross build.
So in order to build for ARM, those files have to be copied from `./res/nrf52-arm/` to `.cargo/config.toml` and `./Cargo.toml`. 

# VS code

The files `res/nrf52-arm/launch.json` and `res/nrf52-arm/tasks.json` can be moved to a folder `.vscode` (in the root folder of the project)
to support debugging within VS code.
`launch.json` refers to a svd file in `./res/` (so the svd file has to be moved there, or `launch.json` to be adapted).


# Build, flash and run

- a symlink `rust-exercises` in the root folder of the project needs to link to a checkout of 
  `https://github.com/ferrous-systems/rust-exercises.git` (git tag v1.10.0)
- the relevant cargo toolchain needs to be installed
  `rustup target add thumbv7em-none-eabihf`

$ cargo run --target=thumbv7em-none-eabihf --example lms_demo_nrf52 -- --allow-erase-all


# Debugging

Here the relevant software may not be completely described...

- `gdb-multiarch` is needed
- `probe-rs` was installed via `cargo install probe-rs --locked --features cli`

Start the tools:

```
  probe-rs gdb --chip nRF52840_xxAA
  gdb-multiarch
```

In `gdb`, connect, load executable and reset:

```
  target remote :1337
  file target/thumbv7em-none-eabihf/debug/examples/lms_demo_nrf52
  mon reset halt
```
