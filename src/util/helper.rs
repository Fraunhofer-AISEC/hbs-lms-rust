pub fn is_odd(x: usize) -> bool {
    x % 2 == 1
}

pub fn read<'a>(src: &'a [u8], length: usize, index: &usize) -> &'a [u8] {
    &src[*index..*index + length]
}

pub fn read_and_advance<'a>(src: &'a [u8], length: usize, index: &mut usize) -> &'a [u8] {
    let result = read(src, length, index);
    *index += length;
    result
}

#[macro_export]
#[doc(hidden)]
macro_rules! extract_or {
    ($x:expr, $or:expr) => {
        match $x {
            None => return $or,
            Some(x) => x,
        }
    };
}
