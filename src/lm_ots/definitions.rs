use crate::util::{
    coef::coef,
    hash::{Hasher, Sha256Hasher},
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LmotsAlgorithmType {
    LmotsReserved = 0,
    LmotsSha256N32W1 = 1,
    LmotsSha256N32W2 = 2,
    LmotsSha256N32W4 = 3,
    LmotsSha256N32W8 = 4,
}

impl LmotsAlgorithmType {
    pub fn get_parameter(self) -> LmotsAlgorithmParameter {
        LmotsAlgorithmParameter::get(self)
    }

    pub fn from_u32(x: u32) -> Option<Self> {
        match x {
            0 => Some(LmotsAlgorithmType::LmotsReserved),
            1 => Some(LmotsAlgorithmType::LmotsSha256N32W1),
            2 => Some(LmotsAlgorithmType::LmotsSha256N32W2),
            3 => Some(LmotsAlgorithmType::LmotsSha256N32W4),
            4 => Some(LmotsAlgorithmType::LmotsSha256N32W8),
            _ => None,
        }
    }
}

pub type IType = [u8; 16];
pub type QType = [u8; 4];

#[derive(Debug, Clone, Copy)]
pub struct LmotsAlgorithmParameter {
    pub n: u16,
    pub w: u8,
    pub p: u16,
    pub ls: u8,
    pub _type: LmotsAlgorithmType,
}

impl LmotsAlgorithmParameter {
    pub fn get(_type: LmotsAlgorithmType) -> Self {
        match _type {
            LmotsAlgorithmType::LmotsReserved => panic!("Reserved parameter type."),
            LmotsAlgorithmType::LmotsSha256N32W1 => {
                LmotsAlgorithmParameter::internal_get(32, 1, LmotsAlgorithmType::LmotsSha256N32W1)
            }
            LmotsAlgorithmType::LmotsSha256N32W2 => {
                LmotsAlgorithmParameter::internal_get(32, 2, LmotsAlgorithmType::LmotsSha256N32W2)
            }
            LmotsAlgorithmType::LmotsSha256N32W4 => {
                LmotsAlgorithmParameter::internal_get(32, 4, LmotsAlgorithmType::LmotsSha256N32W4)
            }
            LmotsAlgorithmType::LmotsSha256N32W8 => {
                LmotsAlgorithmParameter::internal_get(32, 8, LmotsAlgorithmType::LmotsSha256N32W8)
            }
        }
    }

    #[allow(clippy::clippy::many_single_char_names)]
    fn internal_get(n: u16, w: u8, _type: LmotsAlgorithmType) -> Self {
        // Compute p and ls depending on n and w (see RFC8554 Appendix B.)
        let u = ((8.0 * n as f64) / w as f64).ceil();
        let v =
            ((((2usize.pow(w as u32) - 1) as f64 * u).log2() + 1.0f64).floor() / w as f64).ceil();
        let ls: u8 = (16 - (v as usize * w as usize)) as u8;
        let p: u16 = (u as u64 + v as u64) as u16;

        LmotsAlgorithmParameter { n, w, p, ls, _type }
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

    pub fn get_hasher(&self) -> Box<dyn Hasher> {
        match self._type {
            LmotsAlgorithmType::LmotsReserved => panic!("Reserved parameter type."),
            LmotsAlgorithmType::LmotsSha256N32W1 => Box::new(Sha256Hasher::new()),
            LmotsAlgorithmType::LmotsSha256N32W2 => Box::new(Sha256Hasher::new()),
            LmotsAlgorithmType::LmotsSha256N32W4 => Box::new(Sha256Hasher::new()),
            LmotsAlgorithmType::LmotsSha256N32W8 => Box::new(Sha256Hasher::new()),
        }
    }
}

#[allow(non_snake_case)]
pub struct LmotsPrivateKey {
    pub parameter: LmotsAlgorithmParameter,
    pub I: IType,
    pub q: QType,
    pub key: Vec<Vec<u8>>,
}

#[allow(non_snake_case)]
impl LmotsPrivateKey {
    pub fn new(I: IType, q: QType, parameter: LmotsAlgorithmParameter, key: Vec<Vec<u8>>) -> Self {
        LmotsPrivateKey {
            parameter,
            I,
            q,
            key,
        }
    }

    pub fn get_flat_key(&self) -> Vec<u8> {
        let copy = self.key.clone();
        copy.into_iter().flatten().collect()
    }
}

#[allow(non_snake_case)]
pub struct LmotsPublicKey {
    pub parameter: LmotsAlgorithmParameter,
    pub I: IType,
    pub q: QType,
    pub key: Vec<u8>,
}

#[allow(non_snake_case)]
impl LmotsPublicKey {
    pub fn new(I: IType, q: QType, parameter: LmotsAlgorithmParameter, key: Vec<u8>) -> Self {
        LmotsPublicKey {
            parameter,
            I,
            q,
            key,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    macro_rules! generate_parameter_test {
        ($name:ident, $type:expr, $n:literal, $w:literal, $p:literal, $ls:literal) => {
            #[test]
            fn $name() {
                let parameter = LmotsAlgorithmParameter::get($type);
                assert_eq!(parameter._type, $type);
                assert_eq!(parameter.n, $n);
                assert_eq!(parameter.w, $w);
                assert_eq!(parameter.p, $p);
                assert_eq!(parameter.ls, $ls);
            }
        };
    }

    generate_parameter_test!(
        lmots_sha256_n32_w1_parameter_test,
        LmotsAlgorithmType::LmotsSha256N32W1,
        32,
        1,
        265,
        7
    );
    generate_parameter_test!(
        lmots_sha256_n32_w2_parameter_test,
        LmotsAlgorithmType::LmotsSha256N32W2,
        32,
        2,
        133,
        6
    );
    generate_parameter_test!(
        lmots_sha256_n32_w4_parameter_test,
        LmotsAlgorithmType::LmotsSha256N32W4,
        32,
        4,
        67,
        4
    );
    generate_parameter_test!(
        lmots_sha256_n32_w8_parameter_test,
        LmotsAlgorithmType::LmotsSha256N32W8,
        32,
        8,
        34,
        0
    );
}
