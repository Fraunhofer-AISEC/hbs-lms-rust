use paste::paste;
use sha2::{Digest, Sha256};

use super::definitions::*;
use crate::{definitions::D_PBLC, util::ustr::*, util::random::*};

#[allow(non_snake_case)]
pub struct PrivateKey<T: lmots_private_key> {    
    I: I_Type,
    q: q_Type,
    key: T,
}

pub struct PublicKey<T: lmots_public_key> {
    I: I_Type,
    q: q_Type,
    key: T,
}

macro_rules! generate_private_key_gen_impl {
    ($name: ident) => {
        paste! {
            impl PrivateKey<[<$name _PRIVATE_KEY>]> {
                pub fn generate(I: I_Type, q: q_Type) -> Self {
                    let mut key = [[0_u8; $name::n]; $name::p];
            
                    for item in key.iter_mut() {
                        get_random(item);
                    }
            
                    PrivateKey {
                        I, q, key: [<$name _PRIVATE_KEY>]::create(key)
                    }
                }
            }   
        }
    };
}

macro_rules! generate_public_key_gen_impl {
    ($name: ident) => {
        paste! {
            impl PublicKey<[<$name _PUBLIC_KEY>]> {
                pub fn generate(private_key: &PrivateKey<[<$name _PRIVATE_KEY>]>) -> Self {
                    let I = private_key.I;
                    let q = private_key.q;
            
                    const p: usize = $name::p;
                    const w: usize = $name::w;
                    const n: usize = $name::n;
            
                    const max_word_index: usize = (1 << w) - 1;
            
                    let key = private_key.key.get_private_key(); 
                    let mut hasher = Sha256::default();
            
                    let mut y = [[0_u8; n]; p];
            
                    for i in 0..p {
                        let mut tmp = key[i];
                        
                        for j in 0..max_word_index {
                            hasher.update(&I);
                            hasher.update(&q);
                            hasher.update(&u16str(i as u16));
                            hasher.update(&u8str(j as u8));
                            hasher.update(&tmp);
            
                            tmp = hasher.finalize_reset().into();
                        }
                        y[i] = tmp;
                    }
            
                    hasher.update(&I);
                    hasher.update(&q);
                    hasher.update(&D_PBLC);
                    
                    for item in y.iter() {
                        hasher.update(item);
                    }
            
                    let K: [u8; n] = hasher.finalize().into();
            
                    PublicKey {
                        I,
                        q,
                        key: [<$name _PUBLIC_KEY>]::create(K)
                    }
                }
            }
            
        }
    };
}

generate_private_key_gen_impl!(LMOTS_SHA256_N32_W1);
generate_private_key_gen_impl!(LMOTS_SHA256_N32_W2);
generate_private_key_gen_impl!(LMOTS_SHA256_N32_W4);
generate_private_key_gen_impl!(LMOTS_SHA256_N32_W8);

generate_public_key_gen_impl!(LMOTS_SHA256_N32_W1);
generate_public_key_gen_impl!(LMOTS_SHA256_N32_W2);
generate_public_key_gen_impl!(LMOTS_SHA256_N32_W4);
generate_public_key_gen_impl!(LMOTS_SHA256_N32_W8);