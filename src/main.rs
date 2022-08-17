mod set1;

use crate::set1::*;

fn main() {
    println!("{:?}", set1::detect_xor("input/set1_challenge4.txt").unwrap());
}
