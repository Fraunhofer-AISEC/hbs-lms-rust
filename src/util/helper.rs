use core::slice::from_raw_parts_mut;

pub fn is_odd(x: usize) -> bool {
    x % 2 == 1
}

pub fn read_and_advance<'a>(src: &'a [u8], length: usize, index: &mut usize) -> &'a [u8] {
    let result = &src[*index..*index + length];
    *index += length;
    result
}

pub fn split_at_mut<T>(data: &mut [T], mid: usize) -> (&mut [T], &mut [T]) {
    let len = data.len();
    let ptr = data.as_mut_ptr();

    unsafe {
        assert!(mid <= len);

        (
            from_raw_parts_mut(ptr, mid),
            from_raw_parts_mut(ptr.add(mid), len - mid),
        )
    }
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
