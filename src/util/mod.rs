use core::{ops::Index, slice::SliceIndex};
use tinyvec::ArrayVec;
use zeroize::DefaultIsZeroes;

pub mod coef;
pub mod helper;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ArrayVecZeroize<T, const N: usize>(pub ArrayVec<[T; N]>)
where
    T: Copy + Default;

impl<T, const N: usize> DefaultIsZeroes for ArrayVecZeroize<T, N> where T: Copy + Default {}

impl<T, const N: usize> Default for ArrayVecZeroize<T, N>
where
    T: Copy + Default,
{
    #[inline]
    fn default() -> Self {
        Self(ArrayVec::from([T::default(); N]))
    }
}

impl<T, Idx, const N: usize> Index<Idx> for ArrayVecZeroize<T, N>
where
    T: Copy + Default,
    Idx: SliceIndex<[T], Output = T>,
{
    type Output = T;
    #[inline]
    fn index(&self, index: Idx) -> &Self::Output {
        &self.0[index]
    }
}

impl<T, const N: usize> ArrayVecZeroize<T, N>
where
    T: Copy + Default,
{
    #[inline]
    pub fn as_slice(&self) -> &[T] {
        self.0.as_slice()
    }

    #[inline]
    pub fn as_mut_slice(&mut self) -> &mut [T] {
        self.0.as_mut_slice()
    }
}
