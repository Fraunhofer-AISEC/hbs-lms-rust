use core::mem::size_of;

pub type IType = [u8; 16];
pub type QType = [u8; 4];
pub type Seed = [u8; 32];

pub const D_PBLC: [u8; 2] = [0x80, 0x80];
pub const D_MESG: [u8; 2] = [0x81, 0x81];
pub const D_LEAF: [u8; 2] = [0x82, 0x82];
pub const D_INTR: [u8; 2] = [0x83, 0x83];

pub const MAX_N: usize = 32;
pub const MAX_P: usize = 265;

pub const MAX_M: usize = 32;
pub const MAX_H: usize = 25;

pub const MAX_LMS_PRIVATE_KEY_LENGTH: usize = lms_private_key_length();
pub const MAX_LMS_PUBLIC_KEY_LENGTH: usize = lms_public_key_length(MAX_M);
pub const MAX_LMS_SIGNATURE_LENGTH: usize = lms_signature_length(MAX_N, MAX_P, MAX_M, MAX_H);

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
pub const MAX_HSS_PUBLIC_KEY_LENGTH: usize = (4 + 4 + 16 + MAX_M) * MAX_HSS_LEVELS;
pub const MAX_HSS_SIGNATURE_LENGTH: usize =
    (4 + (4 + MAX_N + (MAX_N * MAX_P)) + 4 + (MAX_M * MAX_H)) * MAX_HSS_LEVELS;

pub const MAX_HSS_PRIVATE_KEY_BINARY_REPRESENTATION_LENGTH: usize =
    MAX_HSS_PRIVATE_KEY_LENGTH + MAX_HSS_PUBLIC_KEY_LENGTH + MAX_HSS_SIGNATURE_LENGTH;
