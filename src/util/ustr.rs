use core::convert::TryInto;

pub fn u32str(x: u32) -> [u8; 4] {
    x.to_be_bytes()
}

pub fn u64str(x: u64) -> [u8; 8] {
    x.to_be_bytes()
}

pub fn str32u(x: &[u8]) -> u32 {
    let arr: [u8; 4] = x.try_into().expect("Slice not 4 bytes long");
    u32::from_be_bytes(arr)
}

pub fn str64u(x: &[u8]) -> u64 {
    let arr: [u8; 8] = x.try_into().expect("Slice not 8 bytes long");
    u64::from_be_bytes(arr)
}

pub fn u16str(x: u16) -> [u8; 2] {
    x.to_be_bytes()
}
