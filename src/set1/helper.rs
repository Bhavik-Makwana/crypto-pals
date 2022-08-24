extern crate base64;
use crate::errors::hamming_distance_error::HammingDistanceParsingError;
use crate::set1::types::KeyAndEditDistPair;
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

/*
calculate normalised_edit_distance over whole stream as text has been encrypted
by repeating key over the stream. This will increase the accuracy of the detected
keysize as the edit distance will be smaller when normalized across the entire stream
as incorrect keysizes will have more variation
*/
pub fn normalised_edit_distance(
   bytes: &[u8],
   keysize: usize,
) -> Result<f64, HammingDistanceParsingError> {
   let mut first_bytes;
   let mut second_bytes;
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
         Err(e) => return Err(e),
      }
      i += 1;
   }
   Ok((dist_sum as f64) / (i as f64 + 1.0))
}

pub fn smallest_n_keys(bytes: &[u8], num_of_keys: usize) -> Vec<u32> {
   let mut heap = BinaryHeap::new();
   for i in 2..=40 {
      let pair = KeyAndEditDistPair {
         key: i,
         edit_dist: normalised_edit_distance(&bytes, i).unwrap(),
      };
      heap.push(pair);
   }
   heap
      .iter()
      .take(num_of_keys)
      .map(|x| x.key as u32)
      .collect::<Vec<_>>()
}

pub fn blocks(input: &[u8], keysize: usize) -> Vec<Vec<u8>> {
   let x = input.chunks(keysize).map(|x| x.to_vec()).collect();
   x
}

pub fn transpose<T>(matrix: Vec<Vec<T>>) -> Vec<Vec<T>>
where
   T: Clone + Copy + std::fmt::Debug,
{
   let mut transposed_matrix = vec![Vec::with_capacity(matrix.len()); matrix[0].len()];
   for r in matrix {
      for i in 0..r.len() {
         transposed_matrix[i].push(r[i]);
      }
   }
   transposed_matrix
}

pub fn single_byte_xor(input: &str, key: u8) -> String {
   let decoded = hex::decode(input).unwrap();

   let xor_bytes: Vec<u8> = decoded.iter().map(|&c| c ^ key).collect();

   hex::encode(xor_bytes)
}

pub fn single_byte_xor_bytes(input: &Vec<u8>, key: u8) -> Vec<u8> {
   input.iter().map(|&c| c ^ key).collect()
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
   fn blocks_test() {
      let string = base64::encode("test");
      let bytes = base64::decode(string).unwrap();
      assert_eq!(blocks(&bytes, 2), vec![vec![116, 101], vec![115, 116]]);
   }

   #[test]
   fn transpose_test() {
      let string = base64::encode("test");
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
