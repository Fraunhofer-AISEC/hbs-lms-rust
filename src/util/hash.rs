use sha2::{Digest, Sha256};

pub trait Hasher {
    fn update(&mut self, data: &[u8]);
    fn finalize(self: Box<Self>) -> Vec<u8>;
    fn finalize_reset(&mut self) -> Vec<u8>;
}

pub struct Sha256Hasher {
    hasher: Sha256,
}

impl Sha256Hasher {
    pub fn new() -> Self {
        Sha256Hasher { hasher: Sha256::default() }
    }
}

impl Hasher for Sha256Hasher {
    fn update(&mut self, data: &[u8]) {
        self.hasher.update(data);
    }

    fn finalize(self: Box<Self>) -> Vec<u8> {
        let mut hash = Vec::new();
    
        for value in self.hasher.finalize().into_iter() {
            hash.push(value);
        }

        hash
    }
    
    fn finalize_reset(&mut self) -> Vec<u8> {
        let mut hash = Vec::new();
            
        for value in self.hasher.finalize_reset().into_iter() {
            hash.push(value);
        }

        hash
    }
}