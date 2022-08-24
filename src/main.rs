mod errors;
mod set1;

use crate::errors::*;
use crate::set1::*;

fn main() {
    println!("{:?}", set1::challenge_six("input/set1_challenge6.txt"));
}
