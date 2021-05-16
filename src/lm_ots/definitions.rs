// pub enum lmots_algorithm_type {
//     lmots_reserved       = 0,
//     lmots_sha256_n32_w1  = 1,
//     lmots_sha256_n32_w2  = 2,
//     lmots_sha256_n32_w4  = 3,
//     lmots_sha256_n32_w8  = 4
// }

pub trait lmots_algorithm {
    const n: usize;
    const p: usize;

    type PRIVATE_KEY;

    fn create(key: Self::PRIVATE_KEY) -> Self;
}

macro_rules! create_algorithm_impl {
    ($name:ident, $n:literal, $p:literal) => {
        pub struct $name {
            private_key: [[u8; $n]; $p],
        }

        impl lmots_algorithm for $name {
            const n: usize = $n;
            const p: usize = $p;
        
            type PRIVATE_KEY = [[u8; $n]; $p];
        
            fn create(private_key: Self::PRIVATE_KEY) -> Self {
                $name {
                    private_key
                }
            }
        }
    };
}

create_algorithm_impl!(LMOTS_SHA256_N32_W1, 32, 265);
create_algorithm_impl!(LMOTS_SHA256_N32_W2, 32, 133);
create_algorithm_impl!(LMOTS_SHA256_N32_W4, 32, 67);
create_algorithm_impl!(LMOTS_SHA256_N32_W8, 32, 34);
