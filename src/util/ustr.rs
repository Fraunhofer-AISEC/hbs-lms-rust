use core::convert::TryInto;

pub fn u32str(x: u32) -> [u8; 4] {
    x.to_be_bytes()
}

pub fn str32u(x: &[u8]) -> u32 {
    let arr: [u8; 4] = x.try_into().expect("Slice not 4 bytes long");
    u32::from_be_bytes(arr)
}

pub fn u16str(x: u16) -> [u8; 2] {
    x.to_be_bytes()
}

pub fn u8str(x: u8) -> [u8; 1] {
    x.to_be_bytes()
}
