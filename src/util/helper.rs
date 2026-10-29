pub fn is_odd(x: usize) -> bool {
    x % 2 == 1
}

pub fn read<'a>(src: &'a [u8], length: usize, index: &usize) -> Option<&'a [u8]> {
    src.get(*index..index.checked_add(length)?)
}

pub fn read_and_advance<'a>(src: &'a [u8], length: usize, index: &mut usize) -> Option<&'a [u8]> {
    let result = read(src, length, index)?;
    *index += length;
    Some(result)
}

#[cfg(test)]
pub mod test_helper {
    use crate::{HashChain, Seed};
    use rand::{rngs::OsRng, RngCore};

    pub fn gen_random_seed<H: HashChain>() -> Seed<H> {
        let mut seed = Seed::default();
        OsRng.fill_bytes(seed.as_mut_slice());
        seed
    }
}

#[cfg(test)]
mod tests {
    use super::{read, read_and_advance};

    #[test]
    fn read_checks_bounds() {
        let data = [1u8, 2, 3];
        assert_eq!(read(&data, 3, &0), Some(&data[..]));
        assert_eq!(read(&data, 0, &3), Some(&data[3..]));
        assert_eq!(read(&data, 4, &0), None);
        assert_eq!(read(&data, 1, &3), None);
        assert_eq!(read(&data, usize::MAX, &1), None);
        assert_eq!(read(&data, 1, &usize::MAX), None);
    }

    #[test]
    fn read_and_advance_moves_index_only_on_success() {
        let data = [1u8, 2, 3];
        let mut index = 1;
        assert_eq!(read_and_advance(&data, 3, &mut index), None);
        assert_eq!(index, 1);
        assert_eq!(read_and_advance(&data, 2, &mut index), Some(&data[1..3]));
        assert_eq!(index, 3);
        assert_eq!(read_and_advance(&data, 1, &mut index), None);
        assert_eq!(index, 3);
    }
}
