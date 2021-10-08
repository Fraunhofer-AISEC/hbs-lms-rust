/* Treat byte_string as w-bit integers and return index. */
pub fn coef(byte_string: &[u8], i: u16, w: u8) -> u64 {
    let index = ((i * w as u16) / 8) as usize;

    let digits_per_byte = 8 / w;
    let shift = w as u16 * (!i & (digits_per_byte - 1) as u16);
    let mask: u64 = (1 << w) - 1;

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
