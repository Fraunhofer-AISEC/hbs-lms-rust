use std::fs::File;

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

pub fn read_from_file(file: &mut File, buf: &mut [u8]) {
    use std::io::Read;

    let result = file.read(buf).expect("Could not read file.");
    if result < buf.len() {
        panic!("File has not enough data.");
    }
}
