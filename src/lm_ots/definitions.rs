use paste::paste;

use crate::util::coef::coef;

#[derive(Debug, Clone, Copy)]
pub enum lmots_algorithm_type {
    lmots_reserved       = 0,
    lmots_sha256_n32_w1  = 1,
    lmots_sha256_n32_w2  = 2,
    lmots_sha256_n32_w4  = 3,
    lmots_sha256_n32_w8  = 4
}

pub type I_Type = [u8; 16];
pub type q_Type = [u8; 4];

pub trait lmots_algorithm {
    const n: usize;
    const p: usize;
    const w: usize;
    const ls: usize;
    const _type: lmots_algorithm_type;

    fn checksum(byte_string: &[u8]) -> u16;
}

pub trait lmots_private_key {
    type PRIVATE_KEY;
    const _type: lmots_algorithm_type;
    fn create(private_key: Self::PRIVATE_KEY) -> Self;
    fn get_private_key(&self) -> Self::PRIVATE_KEY;
}

pub trait lmots_public_key {
    type PUBLIC_KEY;
    const _type: lmots_algorithm_type;
    fn create(public_key: Self::PUBLIC_KEY) -> Self;
}

macro_rules! create_algorithm_impl {
    ($name:ident, $type:expr, $n:literal, $p:literal, $w:literal, $ls:literal) => {
        // Empty struct per algorithm type to hold values for n, w, p and ls
        pub struct $name { }

        // Implement lmots_algorithm trait to save constants
        impl lmots_algorithm for $name {
            const n: usize = $n;
            const p: usize = $p;
            const w: usize = $w;
            const ls: usize = $ls;
            const _type: lmots_algorithm_type = $type;

            fn checksum(byte_string: &[u8]) -> u16 {
                let mut sum = 0_u16;
                const max: usize = $n * 8 / $w;
                const max_word_size: usize = (1 << $w) - 1;

                for i in 0..max {
                    sum += (max_word_size - coef(byte_string, i as u64, $w) as usize) as u16;
                }

                sum
            }
        }

        // Generate private key implementation
        paste! {
            pub struct [<$name _PRIVATE_KEY>] {
                private_key: [[u8; $n]; $p],
            }
        
            impl lmots_private_key for [<$name _PRIVATE_KEY>] {
                type PRIVATE_KEY = [[u8; $n]; $p];

                const _type: lmots_algorithm_type = $type;

                fn create(private_key: Self::PRIVATE_KEY) -> Self {
                    [<$name _PRIVATE_KEY>] {
                        private_key,
                    }
                }

                fn get_private_key(&self) -> Self::PRIVATE_KEY {
                    self.private_key
                }
            }           
        }

        // Generate public key implementation
        paste! {
            pub struct [<$name _PUBLIC_KEY>] {
                public_key: [u8; $n],
            }

            impl lmots_public_key for [<$name _PUBLIC_KEY>] {
                type PUBLIC_KEY = [u8; $n];
                const _type: lmots_algorithm_type = $type;

                fn create(public_key: Self::PUBLIC_KEY) -> Self {
                    [<$name _PUBLIC_KEY>] {
                        public_key
                    }
                }
            }
        }
    };
}

create_algorithm_impl!(LMOTS_SHA256_N32_W1, lmots_algorithm_type::lmots_sha256_n32_w1, 32, 265, 1, 7);
create_algorithm_impl!(LMOTS_SHA256_N32_W2, lmots_algorithm_type::lmots_sha256_n32_w2, 32, 133, 2, 6);
create_algorithm_impl!(LMOTS_SHA256_N32_W4, lmots_algorithm_type::lmots_sha256_n32_w4, 32, 67, 4, 4);
create_algorithm_impl!(LMOTS_SHA256_N32_W8, lmots_algorithm_type::lmots_sha256_n32_w8, 32, 34, 8, 0);