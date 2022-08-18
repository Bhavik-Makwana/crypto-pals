use crate::set1::error::HammingDistanceParsingError;

pub fn hamming_distance(string1: &str, string2: &str) -> Result<u32, HammingDistanceParsingError> {
    let bytes1 = string1.as_bytes();
    let bytes2 = string2.as_bytes();

    if bytes1.len() != bytes2.len() {
        return Err(HammingDistanceParsingError::new("bytes differ in length"));
    }
    
    Ok(bytes1.iter().zip(bytes2.iter()).fold(0, |acc, (b1, b2)| acc + (*b1 ^ *b2).count_ones() as u32))

}

#[cfg(test)]
mod tests {
 use super::*;
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
 fn hamming_distance_returns_error () {
    let str1 = "this is a tests";
    let str2 = "wokka wokka!!!";
    assert_eq!(hamming_distance(str1, str2), Err(HammingDistanceParsingError::new("bytes differ in length")));
 }
}