use crate::lm_ots::definitions::IType;
use crate::lm_ots::definitions::LmotsPrivateKey;
use crate::lm_ots::definitions::LmotsPublicKey;
use crate::lm_ots::definitions::QType;

use self::definitions::Seed;
use self::parameter::LmotsParameter;

pub mod definitions;
mod keygen;
pub mod parameter;
pub mod signing;
pub mod verify;

pub fn generate_private_key<OTS: LmotsParameter>(
    q: QType,
    i: IType,
    seed: Seed,
) -> LmotsPrivateKey<OTS> {
    keygen::generate_private_key(i, q, seed)
}

pub fn generate_public_key<OTS: LmotsParameter>(
    private_key: &LmotsPrivateKey<OTS>,
) -> LmotsPublicKey<OTS> {
    keygen::generate_public_key(private_key)
}
