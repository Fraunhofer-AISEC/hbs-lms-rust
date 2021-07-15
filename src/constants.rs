use core::mem::size_of;

pub const ILen: usize = 16;
pub const SEED_LEN: usize = 32;

pub type IType = [u8; ILen];
pub type Seed = [u8; SEED_LEN];
pub type QType = [u8; 4];

pub const D_PBLC: [u8; 2] = [0x80, 0x80];
pub const D_MESG: [u8; 2] = [0x81, 0x81];
pub const D_LEAF: [u8; 2] = [0x82, 0x82];
pub const D_INTR: [u8; 2] = [0x83, 0x83];

pub const TOPSEED_SEED: usize = 23;
pub const TOPSEED_LEN: usize = TOPSEED_SEED + 32;
pub const TOPSEED_D: usize = 20;
pub const TOPSEED_WHICH: usize = 22;
pub const D_TOPSEED: u16 = 0xfefe;

pub const PRG_I: usize = 0;
pub const PRG_Q: usize = 16;
pub const PRG_J: usize = 20;
pub const PRG_FF: usize = 22;
pub const PRG_SEED: usize = 23;

pub const SEED_CHILD_SEED: u16 = !1;

pub const fn PRG_LEN(seed_len: usize) -> usize {
    23 + seed_len
}

pub const MAX_HASH: usize = 32;

pub const PRG_MAX_LEN: usize = PRG_LEN(MAX_HASH);

pub const MAX_P: usize = 265;
pub const MAX_H: usize = 25;

pub const RFC_PRIVATE_KEY_SIZE: usize = 8 + MAX_HSS_LEVELS + size_of::<Seed>() + size_of::<IType>();

pub const MAX_LMS_PRIVATE_KEY_LENGTH: usize = lms_private_key_length();
pub const MAX_LMS_PUBLIC_KEY_LENGTH: usize = lms_public_key_length(MAX_HASH);
pub const MAX_LMS_SIGNATURE_LENGTH: usize = lms_signature_length(MAX_HASH, MAX_P, MAX_HASH, MAX_H);

pub const fn lms_signature_length(n: usize, p: usize, m: usize, h: usize) -> usize {
    4 + (4 + n + (n * p)) + 4 + (m * h)
}

pub const fn lms_public_key_length(m: usize) -> usize {
    4 + 4 + 16 + m
}

pub const fn lms_private_key_length() -> usize {
    4 + 4 + size_of::<IType>() + 4 + size_of::<Seed>()
}

pub const MAX_HSS_LEVELS: usize = 8;

pub const MAX_HSS_PRIVATE_KEY_LENGTH: usize = MAX_LMS_PRIVATE_KEY_LENGTH * MAX_HSS_LEVELS;
pub const MAX_HSS_PUBLIC_KEY_LENGTH: usize = (4 + 4 + 16 + MAX_HASH) * MAX_HSS_LEVELS;
pub const MAX_HSS_SIGNATURE_LENGTH: usize =
    (4 + (4 + MAX_HASH + (MAX_HASH * MAX_P)) + 4 + (MAX_HASH * MAX_H)) * MAX_HSS_LEVELS;

pub const MAX_HSS_PRIVATE_KEY_BINARY_REPRESENTATION_LENGTH: usize =
    MAX_HSS_PRIVATE_KEY_LENGTH + MAX_HSS_PUBLIC_KEY_LENGTH + MAX_HSS_SIGNATURE_LENGTH;
