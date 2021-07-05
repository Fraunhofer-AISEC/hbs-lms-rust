use core::{
    convert::TryFrom,
    ops::{Index, IndexMut},
    slice::Iter,
};

use arrayvec::ArrayVec;

#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct DynamicArray<T: Clone + Default, const ELEMENTS: usize> {
    data: ArrayVec<T, ELEMENTS>,
}

impl<T: Clone + Default, const ELEMENTS: usize> DynamicArray<T, ELEMENTS> {
    pub fn new() -> Self {
        Self {
            data: ArrayVec::new(),
        }
    }

    pub fn len(&self) -> usize {
        self.data.len()
    }

    pub fn from_slice(data: &[T]) -> Self {
        let data = ArrayVec::try_from(data).expect("Array must have enough capacity.");
        Self { data }
    }

    pub fn as_slice(&self) -> &[T] {
        self.data.as_slice()
    }

    pub fn as_mut_slice(&mut self) -> &mut [T] {
        self.data.as_mut_slice()
    }

    pub unsafe fn set_size(&mut self, size: usize) {
        if size > ELEMENTS {
            panic!("Size is larger than array.")
        }
        self.data.set_len(size);
    }

    pub fn append(&mut self, data: &[T]) {
        for x in data {
            self.data.push(x.clone());
        }
    }

    pub fn iter(&self) -> Iter<T> {
        self.data.iter()
    }

    pub fn into_iter(self) -> impl Iterator<Item = T> {
        self.data.into_iter()
    }

    pub fn push(&mut self, element: T) {
        self.data.push(element)
    }
}

impl<T: Clone + Default, const ELEMENTS: usize> Index<usize> for DynamicArray<T, ELEMENTS> {
    type Output = T;
    fn index(&self, index: usize) -> &Self::Output {
        &self.data[index]
    }
}

impl<T: Clone + Default, const ELEMENTS: usize> IndexMut<usize> for DynamicArray<T, ELEMENTS> {
    fn index_mut(&mut self, index: usize) -> &mut Self::Output {
        &mut self.data[index]
    }
}
