use crate::constants::*;
use crate::hasher::Hasher;
use crate::lm_ots::definitions::LmotsPrivateKey;
use crate::lm_ots::definitions::LmotsPublicKey;

use self::parameters::LmotsParameter;

pub mod definitions;
mod keygen;
pub mod parameters;
pub mod signing;
pub mod verify;

pub fn generate_private_key<H: Hasher>(
    q: QType,
    i: IType,
    seed: Seed,
    lmots_parameter: LmotsParameter<H>,
) -> LmotsPrivateKey<H> {
    keygen::generate_private_key(i, q, seed, lmots_parameter)
}

pub fn generate_public_key<H: Hasher>(private_key: &LmotsPrivateKey<H>) -> LmotsPublicKey<H> {
    keygen::generate_public_key(private_key)
}
