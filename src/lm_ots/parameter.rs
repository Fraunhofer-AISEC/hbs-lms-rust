use crate::{
    constants::MAX_N,
    hasher::{sha256::Sha256Hasher, Hasher},
    util::coef::coef,
};

pub trait LmotsParameter: Hasher {
    fn get_n(&self) -> u16;
    fn get_w(&self) -> u8;
    fn get_type(&self) -> u16;

    fn get_p(&self) -> u16 {
        // Compute p and ls depending on n and w (see RFC8554 Appendix B.)
        let u = ((8.0 * self.get_n() as f64) / self.get_w() as f64).ceil();
        let v = ((((2usize.pow(self.get_w() as u32) - 1) as f64 * u).log2() + 1.0f64).floor()
            / self.get_w() as f64)
            .ceil();
        let p: u16 = (u as u64 + v as u64) as u16;
        p
    }

    fn get_ls(&self) -> u8 {
        // Compute p and ls depending on n and w (see RFC8554 Appendix B.)
        let u = ((8.0 * self.get_n() as f64) / self.get_w() as f64).ceil();
        let v = ((((2usize.pow(self.get_w() as u32) - 1) as f64 * u).log2() + 1.0f64).floor()
            / self.get_w() as f64)
            .ceil();
        let ls: u8 = (16 - (v as usize * self.get_w() as usize)) as u8;

        ls
    }

    fn checksum(&self, byte_string: &[u8]) -> u16 {
        let mut sum = 0_u16;
        let max: u64 = ((self.get_n() * 8) as f64 / self.get_w() as f64) as u64;
        let max_word_size: u64 = (1 << self.get_w()) - 1;

        for i in 0..max {
            sum += (max_word_size - coef(byte_string, i, self.get_w() as u64)) as u16;
        }

        sum << self.get_ls()
    }
}

macro_rules! generate_parameter_type {
    ($name:ident, $n:literal, $w:literal, $p:literal, $ls:literal, $type:literal, $hasher:ident) => {
        pub struct $name {
            hasher: $hasher,
        }

        impl LmotsParameter for $name {
            fn get_n(&self) -> u16 {
                $n
            }

            fn get_w(&self) -> u8 {
                $w
            }

            fn get_p(&self) -> u16 {
                $p
            }

            fn get_ls(&self) -> u8 {
                $ls
            }

            fn get_type(&self) -> u16 {
                $type
            }
        }

        impl Hasher for $name {
            fn update(&mut self, data: &[u8]) {
                self.hasher.update(data)
            }

            fn finalize(self) -> crate::util::dynamic_array::DynamicArray<u8, MAX_N> {
                self.hasher.finalize()
            }

            fn finalize_reset(&mut self) -> crate::util::dynamic_array::DynamicArray<u8, MAX_N> {
                self.hasher.finalize_reset()
            }
        }
    };
}

generate_parameter_type!(LmotsSha256N32W1, 32, 1, 265, 7, 1, Sha256Hasher);
generate_parameter_type!(LmotsSha256N32W2, 32, 2, 133, 6, 2, Sha256Hasher);
generate_parameter_type!(LmotsSha256N32W4, 32, 4, 67, 4, 3, Sha256Hasher);
generate_parameter_type!(LmotsSha256N32W8, 32, 8, 34, 0, 4, Sha256Hasher);
