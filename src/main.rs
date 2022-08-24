#![feature(test)]
extern crate test;
mod errors;
mod set1;

fn main() {
    println!("msg: {:?}", set1::detect_ecb("input/set1_challenge8.txt"));
}
