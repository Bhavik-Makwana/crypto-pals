use std::cmp::Ordering;

#[derive(PartialEq)]
pub struct KeyAndEditDistPair {
    pub key: usize,
    pub edit_dist: f64,
}

impl PartialOrd for KeyAndEditDistPair {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        other.edit_dist.partial_cmp(&self.edit_dist)
    }
}

impl Ord for KeyAndEditDistPair {
    fn cmp(&self, other: &Self) -> Ordering {
        self.partial_cmp(other).unwrap()
    }
}

impl Eq for KeyAndEditDistPair {}

pub struct DecipheredText {
    pub text: String,
    pub key: u8,
    pub score: i32,
}
