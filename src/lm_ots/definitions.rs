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

pub struct lmots_algorithm_parameter {
    n: u16,
    w: u8,
    p: u16,
    ls: u8,
    _type: lmots_algorithm_type
}

impl lmots_algorithm_parameter {
    pub fn get(_type: lmots_algorithm_type) -> Self {
        match _type {
            lmots_algorithm_type::lmots_reserved => panic!("Reserved parameter type."),
            lmots_algorithm_type::lmots_sha256_n32_w1 => lmots_algorithm_parameter::internal_get(32, 1, lmots_algorithm_type::lmots_sha256_n32_w1),
            lmots_algorithm_type::lmots_sha256_n32_w2 => lmots_algorithm_parameter::internal_get(32, 2, lmots_algorithm_type::lmots_sha256_n32_w2),
            lmots_algorithm_type::lmots_sha256_n32_w4 => lmots_algorithm_parameter::internal_get(32, 4, lmots_algorithm_type::lmots_sha256_n32_w4),
            lmots_algorithm_type::lmots_sha256_n32_w8 => lmots_algorithm_parameter::internal_get(32, 8, lmots_algorithm_type::lmots_sha256_n32_w8),
        }
    }

    fn internal_get(n: u16, w: u8, _type: lmots_algorithm_type) -> Self {
        // Compute p and ls depending on n and w (see RFC8554 Appendix B.)
        let u = ((8.0 * n as f64) / w as f64).ceil();
        let v = ((((2usize.pow(w as u32) - 1) as f64 * u).log2() + 1.0f64).floor() / w as f64).ceil();
        let ls: u8 = (16 - (v as usize * w as usize)) as u8;
        let p: u16 = (u as u64 + v as u64) as u16;

        lmots_algorithm_parameter {
            n,
            w,
            p,
            ls,
            _type
        }
    }

    pub fn checksum(&self, byte_string: &[u8]) -> u16 {
        let mut sum = 0_u16;
        let max: u64 = ((self.n * 8) as f64 / self.w as f64) as u64;
        let max_word_size: u64 = (1 << self.w) - 1;

        for i in 0..max {
            sum += (max_word_size - coef(byte_string, i, self.w as u64)) as u16;
        }

        sum
    }
}

pub struct LmotsKey {
    parameter: lmots_algorithm_parameter,
    key: Box<[u8]>,
}