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

    pub fn is_empty(&self) -> bool {
        self.len() == 0
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

    pub fn append(&mut self, data: &[T]) {
        for x in data {
            self.data.push(x.clone());
        }
    }

    pub fn iter(&self) -> Iter<T> {
        self.data.iter()
    }

    pub fn push(&mut self, element: T) {
        self.data.push(element)
    }

    pub fn clear(&mut self) {
        self.data.clear()
    }
}

impl<'a, T: Clone + Default, const ELEMENTS: usize> IntoIterator for DynamicArray<T, ELEMENTS> {
    type Item = T;
    type IntoIter = arrayvec::IntoIter<T, ELEMENTS>;
    fn into_iter(self) -> Self::IntoIter {
        self.data.into_iter()
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
        // This makes it possible to add a new element on top with the Index accessor
        if index == self.data.len() {
            self.push(Default::default());
        }
        &mut self.data[index]
    }
}
