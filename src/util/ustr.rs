pub fn u32str(x: u32) -> [u8; 4] {
    x.to_be_bytes()
}

pub fn str32u(x: &[u8; 4]) -> u32 {
    unsafe { std::mem::transmute::<[u8; 4], u32>(*x).to_be() }
}

pub fn u16str(x: u16) -> [u8; 2] {
    x.to_be_bytes()
}

pub fn u8str(x: u8) -> [u8; 1] {
    x.to_be_bytes()
}
