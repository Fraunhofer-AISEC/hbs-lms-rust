pub fn is_power_of_two(x: usize) -> bool {
    let result = x & (x - 1);
    result == 0
}

pub fn is_odd(x: usize) -> bool {
    x % 2 == 1
}

pub fn copy_and_advance(src: &[u8], dst: &mut [u8], index: &mut usize) {
    dst[*index..*index + src.len()].copy_from_slice(src);
    *index += src.len();
}

pub fn read_and_advance<'a>(src: &'a [u8], length: usize, index: &mut usize) -> &'a [u8] {
    let result = &src[*index..*index + length];
    *index += length;
    result
}
