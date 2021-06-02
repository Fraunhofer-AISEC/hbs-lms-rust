pub fn is_power_of_two(x: usize) -> bool {
    let result = x & (x - 1);
    result == 0
}

pub fn is_odd(x: usize) -> bool {
    x % 2 == 1
}

pub fn insert(array: &[u8], vec: &mut Vec<u8>) {
    for b in array {
        vec.push(*b);
    }
}
