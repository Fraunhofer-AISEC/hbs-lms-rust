use crate::lm_ots::definitions::QType;
use crate::lm_ots::definitions::IType;
use crate::lm_ots::definitions::LmotsAlgorithmType;
use crate::lm_ots::definitions::LmotsPrivateKey;

pub mod definitions;
mod keygen;
mod signing;
mod verify;

pub fn generate_private_key(q: QType, i: IType, _type: LmotsAlgorithmType) -> LmotsPrivateKey {
    keygen::generate_private_key(i, q, _type)
}