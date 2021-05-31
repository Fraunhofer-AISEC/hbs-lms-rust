pub fn is_power_of_two(x: usize) -> bool {
    let result = x & (x - 1);
    result == 0
}