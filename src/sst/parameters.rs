use crate::{constants::SST_SIZE, Error};

use zeroize::{Zeroize, ZeroizeOnDrop};

#[derive(Debug, Clone, PartialEq, Eq, Zeroize, ZeroizeOnDrop)]
pub struct SstExtension {
    signing_entity_idx: u8, // from 1 to (2^l0_top_div)
    l0_top_div: u8, // e.g. L-0 LMS height of 5 and l0_top_div = 3: division top/bottom is 3/2 -> 2^3 = 8 signing entities
}

impl SstExtension {
    pub fn new(signing_entity_idx: u8, l0_top_div: u8) -> Result<Self, Error> {
        (signing_entity_idx != 0 && l0_top_div != 0)
            .then_some(())
            .ok_or(Error::new())?;
        (signing_entity_idx as u32 <= 2u32.pow(l0_top_div as u32))
            .then_some(())
            .ok_or(Error::new())?;
        Ok(Self {
            signing_entity_idx,
            l0_top_div,
        })
    }

    pub(crate) fn from_slice(data: &[u8]) -> Result<Self, ()> {
        (data.len() == SST_SIZE).then_some(()).ok_or(())?;
        Self::new(data[0], data[1]).map_err(|_| ())
    }

    pub fn signing_entity_idx(&self) -> u8 {
        self.signing_entity_idx
    }

    pub(crate) fn l0_top_div(&self) -> u8 {
        self.l0_top_div
    }
}
