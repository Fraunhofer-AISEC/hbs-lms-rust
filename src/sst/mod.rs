//! Module sst

// TODO/Review: not sure whether that's an elegant solution
mod gen_key;
pub use gen_key::*;

// public only inside crate
pub(crate) mod helper;
pub(crate) mod parameters;
