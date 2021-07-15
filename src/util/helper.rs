pub fn is_odd(x: usize) -> bool {
    x % 2 == 1
}

pub fn read_and_advance<'a>(src: &'a [u8], length: usize, index: &mut usize) -> &'a [u8] {
    let result = &src[*index..*index + length];
    *index += length;
    result
}

#[macro_export]
macro_rules! extract_or_return {
    ($x:expr) => {
        match $x {
            None => return None,
            Some(x) => x,
        };
    };
}

#[macro_export]
macro_rules! extract_or {
    ($x:expr, $or:expr) => {
        match $x {
            None => return $or,
            Some(x) => x,
        };
    };
}
