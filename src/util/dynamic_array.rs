use core::ops::{Index, IndexMut};

#[derive(Debug, Clone, Copy)]
pub struct DynamicArray<T: Copy + Default, const ELEMENTS: usize> {
    data: [T; ELEMENTS],
    actual_size: usize,
}

impl<T: Copy + Default, const ELEMENTS: usize> DynamicArray<T, ELEMENTS> {
    pub fn new() -> Self {
        DynamicArray {
            data: [T::default(); ELEMENTS],
            actual_size: 0,
        }
    }

    pub fn from_slice(data: &[T]) -> Self {
        let mut copied_data = [T::default(); ELEMENTS];
        copied_data.copy_from_slice(data);
        DynamicArray {
            data: copied_data,
            actual_size: data.len(),
        }
    }

    pub fn get_slice(&self) -> &[T] {
        &self.data[..self.actual_size]
    }

    pub fn get_mut_slice(&mut self) -> &mut [T] {
        &mut self.data[..self.actual_size]
    }

    pub fn append(&mut self, data: &[T]) {
        self.data[self.actual_size..self.actual_size + data.len()].copy_from_slice(data);
    }
}

impl<T: Copy + Default, const ELEMENTS: usize> Default for DynamicArray<T, ELEMENTS> {
    fn default() -> Self {
        DynamicArray::new()
    }
}

impl<T: Copy + Default, const ELEMENTS: usize> Index<usize> for DynamicArray<T, ELEMENTS> {
    type Output = T;
    fn index(&self, index: usize) -> &Self::Output {
        if index > self.actual_size {
            panic!("Index out of bounds");
        }
        &self.data[index]
    }
}

impl<T: Copy + Default, const ELEMENTS: usize> IndexMut<usize> for DynamicArray<T, ELEMENTS> {
    fn index_mut(&mut self, index: usize) -> &mut Self::Output {
        if index > self.actual_size {
            self.actual_size = index;
        }
        &mut self.data[index]
    }
}

impl<'a, T: Copy + Default, const ELEMENTS: usize> IntoIterator for &'a DynamicArray<T, ELEMENTS> {
    type Item = T;
    type IntoIter = DynamicArrayIterator<'a, T, ELEMENTS>;
    fn into_iter(self) -> Self::IntoIter {
        DynamicArrayIterator {
            current_index: 0,
            dynamic_array: &self,
        }
    }
}

pub struct DynamicArrayIterator<'a, T: Copy + Default, const ELEMENTS: usize> {
    current_index: usize,
    dynamic_array: &'a DynamicArray<T, ELEMENTS>,
}

impl<'a, T: Copy + Default, const ELEMENTS: usize> Iterator
    for DynamicArrayIterator<'a, T, ELEMENTS>
{
    type Item = T;
    fn next(&mut self) -> Option<Self::Item> {
        if self.current_index > self.dynamic_array.actual_size {
            return None;
        }
        let ret = Some(self.dynamic_array.data[self.current_index]);
        self.current_index += 1;
        ret
    }
}
