use crate::{
    constants::MAX_N,
    hasher::{sha256::Sha256Hasher, Hasher},
    util::{coef::coef, dynamic_array::DynamicArray},
};

use crate::constants::{IType, QType};

pub trait LmotsParameter: Hasher + Default + Clone {
    const N: usize = Self::OUTPUT_SIZE;
    const W: u8;
    const TYPE: u32;

    fn is_type_correct(_type: u32) -> bool {
        Self::TYPE == _type
    }

    fn get_p() -> u16 {
        // Compute p and ls depending on n and w (see RFC8554 Appendix B.)
        let u = ((8.0 * Self::N as f64) / Self::W as f64).ceil();
        let v = ((((2usize.pow(Self::W as u32) - 1) as f64 * u).log2() + 1.0f64).floor()
            / Self::W as f64)
            .ceil();
        let p: u16 = (u as u64 + v as u64) as u16;
        p
    }

    fn get_ls() -> u8 {
        // Compute p and ls depending on n and w (see RFC8554 Appendix B.)
        let u = ((8.0 * Self::N as f64) / Self::W as f64).ceil();
        let v = ((((2usize.pow(Self::W as u32) - 1) as f64 * u).log2() + 1.0f64).floor()
            / Self::W as f64)
            .ceil();
        let ls: u8 = (16 - (v as usize * Self::W as usize)) as u8;

        ls
    }

    fn checksum(byte_string: &[u8]) -> u16 {
        let mut sum = 0_u16;
        let max: u64 = ((Self::N * 8) as f64 / Self::W as f64) as u64;
        let max_word_size: u64 = (1 << Self::W) - 1;

        for i in 0..max {
            sum += (max_word_size - coef(byte_string, i, Self::W as u64)) as u16;
        }

        sum << Self::get_ls()
    }

    fn get_appended_with_checksum(byte_string: &[u8]) -> DynamicArray<u8, { MAX_N + 2 }> {
        let mut result = DynamicArray::new();

        let checksum = Self::checksum(byte_string);

        result.append(byte_string);

        result.append(&[(checksum >> 8 & 0xff) as u8]);
        result.append(&[(checksum & 0xff) as u8]);

        result
    }
}

macro_rules! generate_parameter_type {
    ($name:ident, $w:literal, $type:literal, $hasher:ident) => {
        #[derive(Default, Clone)]
        pub struct $name {
            hasher: $hasher,
        }

        impl LmotsParameter for $name {
            const W: u8 = $w;
            const TYPE: u32 = $type;
        }

        impl Hasher for $name {
            const OUTPUT_SIZE: usize = $hasher::OUTPUT_SIZE;

            fn get_hasher() -> Self {
                $name {
                    hasher: $hasher::new(),
                }
            }

            fn update(&mut self, data: &[u8]) {
                self.hasher.update(data)
            }

            fn finalize(self) -> crate::util::dynamic_array::DynamicArray<u8, MAX_N> {
                self.hasher.finalize()
            }

            fn finalize_reset(&mut self) -> crate::util::dynamic_array::DynamicArray<u8, MAX_N> {
                self.hasher.finalize_reset()
            }

            #[allow(non_snake_case)]
            fn do_hash_chain(
                &mut self,
                I: &IType,
                q: &QType,
                i: u16,
                from: usize,
                to: usize,
                start: &mut [u8],
            ) {
                self.hasher.do_hash_chain(I, q, i, from, to, start);
            }
        }
    };
}

generate_parameter_type!(LmotsSha256N32W1, 1, 1, Sha256Hasher);
generate_parameter_type!(LmotsSha256N32W2, 2, 2, Sha256Hasher);
generate_parameter_type!(LmotsSha256N32W4, 4, 3, Sha256Hasher);
generate_parameter_type!(LmotsSha256N32W8, 8, 4, Sha256Hasher);
