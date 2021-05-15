pub fn coef(byte_string: &[u8], i: u64, w: u64) -> u64 {
    debug_assert!([1, 2, 4, 8].contains(&w));

    let index = ((i * w) / 8) as usize;
    assert!(index < byte_string.len());

    let digits_per_byte = 8 / w;
    let shift = w as u64 * (!i & (digits_per_byte-1) as u64);
    let mask: u64 = (1<<w) - 1;
    
    (byte_string[index] as u64 >> shift) & mask
}