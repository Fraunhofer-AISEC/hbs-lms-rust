use crate::random::get_random;

use super::definitions::*;

#[allow(non_snake_case)]
pub struct PrivateKey<T: lmots_algorithm> {    
    I: [u8; 16],
    q: [u8; 4],
    key: T,
}

macro_rules! create_private_key_impl {
    ($name:ident) => {
        impl PrivateKey<$name> {
            pub fn generate(I: [u8; 16], q: [u8; 4]) -> Self {
                let mut key = [[0_u8; $name::n]; $name::p];
        
                for item in key.iter_mut() {
                    get_random(item);
                }
        
                PrivateKey {
                    I, q, key: $name::create(key)
                }
            }
        }       
    };
}

create_private_key_impl!(LMOTS_SHA256_N32_W1);
create_private_key_impl!(LMOTS_SHA256_N32_W2);
create_private_key_impl!(LMOTS_SHA256_N32_W4);
create_private_key_impl!(LMOTS_SHA256_N32_W8);