use std::cmp::Ordering;

pub mod scorer;
pub mod io;

extern crate base64;
extern crate hex;

// challenge 4
pub fn detect_xor(filename: &str) -> Result<String, ()> {
    let ciphers = io::lines_from_file(filename);
    let x = ciphers.iter()
        .map(|c| single_byte_xor_cipher(c))
        .map(|(a, _, c)| (a, c))
        .max_by(|(_, a), (_, b)| a.partial_cmp(b).unwrap_or(Ordering::Equal));
    match x {
        Some(v) => Ok(v.0),
        None => Err(()),
    }
}

pub fn single_byte_xor_cipher(input: &str) -> (String, u8, i32) {
    let mut ans: String = "".to_string();
    let mut key: u8 = 0;
    let mut max = 0;
    for k in 0..=255 {
        let s = scorer::single_byte_xor(input, k as u8);
        let p = &hex::decode(s).unwrap();
        let msg = String::from(String::from_utf8_lossy(p));
        let current_score = msg.chars().map(|c| scorer::score(c)).sum();
        if current_score > max {
            max = current_score;
            ans = msg;
            key = k;
        }
    }
    (ans, key, max)
}


pub fn hex_to_base64(input: String) -> String {
    base64::encode(hex::decode(input).unwrap())
}

pub fn xor(buf1: String, buf2: String) -> String {
    let decoded1 = hex::decode(buf1).unwrap();
    let decoded2 = hex::decode(buf2).unwrap();
    let xor_bytes: Vec<u8> = decoded1.iter()
        .zip(decoded2.iter())
        .map(|(d1, d2)| d1 ^ d2)
        .collect();

    hex::encode(xor_bytes)
}

#[cfg(test)]
mod tests {
 use super::*;
 #[test]
 fn converts_hex_to_base64() {
    let input = "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d".to_string();
    let output = "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t";
    assert_eq!(hex_to_base64(input), output);
 }

 #[test]
 fn fixed_xor() {
     let input = "1c0111001f010100061a024b53535009181c".to_string();
     let fix = "686974207468652062756c6c277320657965".to_string();
     assert_eq!(xor(input, fix),"746865206b696420646f6e277420706c6179".to_string())
 }

 #[test]
 fn single_byte_xor() {
    let input = "1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736";
    let (ans, key, _) = single_byte_xor_cipher(input);
    assert_eq!(ans, "Cooking MC's like a pound of bacon");
    assert_eq!(key, 88);
 }

 #[test]
 fn challenge_four() {
    let filename = "input/set1_challenge4.txt";
    let ans = detect_xor(filename);
    assert_eq!(ans, Ok("Now that the party is jumping\n".to_string()));
 }
}
