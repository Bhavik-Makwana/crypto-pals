extern crate base64;
use crate::set1::error::HammingDistanceParsingError;
use crate::set1::pair::KeyAndEditDistPair;
use core::cmp::Ordering;
use std::cmp::Reverse;
use std::collections::BinaryHeap;

pub fn hamming_distance(string1: &str, string2: &str) -> Result<u32, HammingDistanceParsingError> {
   let bytes1 = string1.as_bytes();
   let bytes2 = string2.as_bytes();

   if bytes1.len() != bytes2.len() {
      return Err(HammingDistanceParsingError::new("bytes differ in length"));
   }

   Ok(bytes1
      .iter()
      .zip(bytes2.iter())
      .fold(0, |acc, (b1, b2)| acc + (*b1 ^ *b2).count_ones() as u32))
}

pub fn hamming_distance_bytes(
   bytes1: &[u8],
   bytes2: &[u8],
) -> Result<u32, HammingDistanceParsingError> {
   if bytes1.len() != bytes2.len() {
      return Err(HammingDistanceParsingError::new("bytes differ in length"));
   }

   Ok(bytes1
      .iter()
      .zip(bytes2.iter())
      .fold(0, |acc, (b1, b2)| acc + (*b1 ^ *b2).count_ones() as u32))
}

pub fn normalised_edit_distance(bytes: &[u8], keysize: usize) -> Result<f64, String> {
   let mut first_bytes; // = &bytes[0..keysize];
   let mut second_bytes; // = &bytes[keysize..keysize * 2];
   let len = bytes.len();
   let mut i: usize = 0;
   let mut dist_sum: f64 = 0.0;
   loop {
      if i * 2 * keysize >= len {
         break;
      }
      first_bytes = &bytes[i * keysize..(i + 1) * keysize];
      second_bytes = &bytes[(i + 1) * keysize..(i + 2) * keysize];
      match hamming_distance_bytes(first_bytes, second_bytes) {
         Ok(result) => dist_sum += result as f64 / keysize as f64,
         Err(_) => break,
      }
      i += 1;
   }
   Ok((dist_sum as f64) / (i as f64 + 1.0))
}

pub fn smallest_key(bytes: &[u8]) -> u32 {
   let mut heap = vec![];
   for i in 2..=40 {
      // heap.push((Reverse(normalised_edit_distance(&bytes, i)), i));
      heap.push((normalised_edit_distance(&bytes, i), i));
   }
   heap.sort_by(|x, y| y.0.partial_cmp(&x.0).unwrap());
   println!("{:?}", heap);
   let key_sz = heap.pop().and_then(|x| Some(x.1)).unwrap();
   println!("{:?}", key_sz);
   key_sz as u32
}

pub fn smallest_three_keys(input: &str) -> Vec<u32> {
   let bytes = base64::decode(input).unwrap();
   let mut heap = BinaryHeap::new();
   // let mut heap = vec![];
   for i in 2..=40 {
      let pair = KeyAndEditDistPair {
         key: i,
         edit_dist: normalised_edit_distance(&bytes, i).unwrap(),
      };
      heap.push(pair);
   }
   heap
      .into_sorted_vec()
      .iter()
      .take(3)
      .map(|x| x.key as u32)
      .collect::<Vec<_>>()
}

pub fn blocks(input: &[u8], keysize: usize) -> Vec<Vec<u8>> {
   let x = input.chunks(keysize).map(|x| x.to_vec()).collect();
   x
}

pub fn transpose<T>(m: Vec<Vec<T>>) -> Vec<Vec<T>>
where
   T: Clone + Copy + std::fmt::Debug,
{
   let mut t = vec![Vec::with_capacity(m.len()); m[0].len()];
   for r in m {
      for i in 0..r.len() {
         t[i].push(r[i]);
      }
   }
   t
}

#[cfg(test)]
mod tests {
   use super::*;

   #[test]
   fn normalised_edit_distance_is_0() {
      let string = base64::encode("thithi gonna be normalised");
      let bytes = base64::decode(string).unwrap();
      assert_eq!(normalised_edit_distance(&bytes, 3), Ok(1.6111111111111114));
   }

   #[test]
   fn smallest_three_keys_12_12_12() {
      let string = base64::encode("thithi gonna be normalisedthithi gonna be normalisedthithi gonna be normalisedthithi gonna be normalisedthithi gonna be normalisedthithi gonna be normalised");
      assert_eq!(smallest_three_keys(&string), vec![2]);
   }

   #[test]
   fn blocks_test() {
      let string = base64::encode("testdabc");
      let bytes = base64::decode(string).unwrap();
      assert_eq!(blocks(&bytes, 2), vec![vec![116, 101], vec![115, 116]]);
   }

   #[test]
   fn transpose_test() {
      let string = base64::encode("testdabc");
      let bytes = base64::decode(string).unwrap();
      assert_eq!(
         transpose(blocks(&bytes, 2)),
         vec![vec![116, 115], vec![101, 116]]
      );
   }

   #[test]
   fn hamming_distance_calculates_correctly() {
      let str1 = "this is a test";
      let str2 = "wokka wokka!!!";
      assert_eq!(hamming_distance(str1, str2), Ok(37));
   }

   #[test]
   fn hamming_distance_is_0() {
      let str1 = "this is a test";
      let str2 = "this is a test";
      assert_eq!(hamming_distance(str1, str2), Ok(0));
   }

   #[test]
   fn hamming_distance_bytes_is_0() {
      let str1 = "this is a test";
      let str2 = "this is a test";
      assert_eq!(
         hamming_distance_bytes(str1.as_bytes(), str2.as_bytes()),
         Ok(0)
      );
   }

   #[test]
   fn hamming_distance_returns_error() {
      let str1 = "this is a tests";
      let str2 = "wokka wokka!!!";
      assert_eq!(
         hamming_distance(str1, str2),
         Err(HammingDistanceParsingError::new("bytes differ in length"))
      );
   }
}
