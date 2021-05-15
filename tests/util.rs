#[cfg(test)]
mod tests {
    #[test]
    fn coef_test1() {
        let value = lms::util::coef(&[0x12, 0x34], 7, 1);
        assert_eq!(value, 0);
    }

    #[test]
    fn coef_test2() {
        let value = lms::util::coef(&[0x12, 0x34], 0, 4);
        assert_eq!(value, 1);
    }

    #[test]
    #[should_panic]
    fn coef_test_panic() {
        lms::util::coef(&[0x12, 0x34], 2, 8);
    }
}
