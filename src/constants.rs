use core::mem::size_of;

pub type IType = [u8; 16];
pub type QType = [u8; 4];
pub type Seed = [u8; 32];

pub const D_PBLC: [u8; 2] = [0x80, 0x80];
pub const D_MESG: [u8; 2] = [0x81, 0x81];
pub const D_LEAF: [u8; 2] = [0x82, 0x82];
pub const D_INTR: [u8; 2] = [0x83, 0x83];

pub const MAX_N: usize = 32;
pub const MAX_P: usize = 34;

pub const MAX_M: usize = 32;
pub const MAX_H: usize = 5;

pub const MAX_PRIVATE_KEY_LENGTH: usize = 4 + 4 + size_of::<IType>() + 4 + size_of::<Seed>();
// pub const MAX_SIGNATURE_LENGTH: usize = 4 + 4 + (4 + MAX_N + (MAX_N * MAX_P)) + 4 + (MAX_M * MAX_H);
// pub const MAX_PUBLIC_KEY_LENGTH: usize = 4 + 4 + 4 + 16 + MAX_M;
