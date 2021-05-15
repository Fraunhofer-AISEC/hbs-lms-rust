/* Treat byte_string as w-bit integers and return index. */
pub fn coef(byte_string: &[u8], i: u64, w: u64) -> u64 {
    debug_assert!([1, 2, 4, 8].contains(&w));

    let index = ((i * w) / 8) as usize;
    assert!(index < byte_string.len());

    let digits_per_byte = 8 / w;
    let shift = w as u64 * (!i & (digits_per_byte-1) as u64);
    let mask: u64 = (1<<w) - 1;
    
    (byte_string[index] as u64 >> shift) & mask
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn coef_test1() {
        let value = coef(&[0x12, 0x34], 7, 1);
        assert_eq!(value, 0);
    }

    #[test]
    fn coef_test2() {
        let value = coef(&[0x12, 0x34], 0, 4);
        assert_eq!(value, 1);
    }

    #[test]
    #[should_panic]
    fn coef_test_panic() {
        coef(&[0x12, 0x34], 2, 8);
    }
}
