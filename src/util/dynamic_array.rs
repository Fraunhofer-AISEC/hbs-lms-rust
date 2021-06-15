pub struct DynamicArray<T, const ELEMENTS: usize> {
    data: [T; ELEMENTS],
    actual_size: usize,
}

impl<T, const ELEMENTS: usize> DynamicArray<T, ELEMENTS> {
    pub fn new(data: [T; ELEMENTS], actual_size: usize) -> Self {
        DynamicArray {
            data,
            actual_size
        }
    }

    pub fn get_slice(&self) -> &[T] {
        &self.data[..self.actual_size]
    }
}