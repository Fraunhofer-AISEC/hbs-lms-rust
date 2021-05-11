#[cfg(test)]
mod tests {
    #[test]
    fn it_works() {
        assert_eq!(2 + 2, 4);
    }

    #[test]
    fn multiply_works() {
        assert_eq!(lms::multiply(2), 2 * 2);
    }
}
