use crate::{
    constants::{MAX_PRIVATE_KEY_LENGTH, MAX_PUBLIC_KEY_LENGTH},
    util::dynamic_array::DynamicArray,
};

pub mod custom;
pub mod standard;

pub struct HssKeyPair {
    pub public_key: DynamicArray<u8, MAX_PUBLIC_KEY_LENGTH>,
    pub private_key: DynamicArray<u8, MAX_PRIVATE_KEY_LENGTH>,
}
