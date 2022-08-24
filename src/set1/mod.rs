pub mod helper;
pub mod io;
pub mod scorer;
pub mod types;
use std::cmp::Ordering;
extern crate base64;
extern crate hex;

pub fn challenge_six(filename: &str) -> Vec<String> {
    let lines = io::read_file_no_newline(filename);
    let bytes = base64::decode(lines).unwrap();
    let keys = helper::smallest_n_keys(&bytes, 3);
    // println!("KEY SIZES {:?}", keys);

    let mut res: Vec<_> = vec![];
    for k in keys.iter() {
        let blocks = helper::blocks(&bytes, *k as usize);
        // println!("{} {} ", blocks.len(), blocks[0].len());
        let transpose = helper::transpose(blocks);
        res.push(
            transpose
                .iter()
                .map(|block| single_byte_xor_cipher_bytes(block).key)
                .collect::<Vec<u8>>(),
        );
    }
    // println!("{:?}", res);
    let mut potential_keys: Vec<String> = vec![];
    for i in res.iter() {
        let key = i.iter().map(|&b| b as char).collect();
        potential_keys.push(key);
    }
    potential_keys
}

// challenge 5
pub fn repeating_key_xor(filename: &str, key: &str) -> String {
    let lines = io::read_file(filename);
    let lines_bytes = lines.as_bytes();
    let repeating_key: String = key
        .to_string()
        .chars()
        .cycle()
        .take(lines_bytes.len())
        .collect();
    let key_bytes = repeating_key.as_bytes();
    let xor_value: Vec<u8> = lines_bytes
        .iter()
        .zip(key_bytes.iter())
        .map(|(a, b)| a ^ b)
        .collect();

    hex::encode(xor_value)
}

// challenge 4
pub fn detect_xor(filename: &str) -> Result<String, ()> {
    let ciphers = io::lines_from_file(filename);
    let x = ciphers
        .iter()
        .map(|c| single_byte_xor_cipher(c))
        .map(|deciphered_text| (deciphered_text.text, deciphered_text.score))
        .max_by(|(_, a), (_, b)| a.partial_cmp(b).unwrap_or(Ordering::Equal));
    match x {
        Some(v) => Ok(v.0),
        None => Err(()),
    }
}

pub struct DecipheredText {
    text: String,
    key: u8,
    score: i32,
}

// Challenge 3
pub fn single_byte_xor_cipher(input: &str) -> DecipheredText {
    let mut ans: String = "".to_string();
    let mut key: u8 = 0;
    let mut max = 0;
    for k in 0..=255 {
        let xor_text = scorer::single_byte_xor(input, k as u8);
        let deciphered_text_bytes = &hex::decode(xor_text).unwrap();
        let deciphered_text = String::from(String::from_utf8_lossy(deciphered_text_bytes));
        let current_score = deciphered_text.chars().map(|c| scorer::score(c)).sum();
        if current_score > max {
            max = current_score;
            ans = deciphered_text;
            key = k;
        }
    }

    DecipheredText {
        text: ans,
        key: key,
        score: max,
    }
}

pub fn single_byte_xor_cipher_bytes(input: &Vec<u8>) -> DecipheredText {
    let mut ans: String = "".to_string();
    let mut key: u8 = 0;
    let mut max = 0;
    for k in 0..=255 {
        let xor_text = scorer::single_byte_xor_bytes(input, k as u8);
        // let deciphered_text_bytes = &hex::decode(xor_text).unwrap();
        let deciphered_text = String::from(String::from_utf8_lossy(&xor_text));
        let current_score = deciphered_text.chars().map(|c| scorer::score(c)).sum();
        if current_score > max {
            max = current_score;
            ans = deciphered_text;
            key = k;
        }
    }

    DecipheredText {
        text: ans,
        key: key,
        score: max,
    }
}

// Challenge 1
pub fn hex_to_base64(input: String) -> String {
    base64::encode(hex::decode(input).unwrap())
}

// Challenge 2
pub fn xor(buf1: String, buf2: String) -> String {
    let decoded1 = hex::decode(buf1).unwrap();
    let decoded2 = hex::decode(buf2).unwrap();
    let xor_bytes: Vec<u8> = decoded1
        .iter()
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
        assert_eq!(
            xor(input, fix),
            "746865206b696420646f6e277420706c6179".to_string()
        )
    }

    #[test]
    fn single_byte_xor() {
        let input = "1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736";
        let deciphered_text = single_byte_xor_cipher(input);
        assert_eq!(deciphered_text.text, "Cooking MC's like a pound of bacon");
        assert_eq!(deciphered_text.key, 88);
    }

    #[test]
    fn challenge_four() {
        let filename = "input/set1_challenge4.txt";
        let ans = detect_xor(filename);
        assert_eq!(ans, Ok("Now that the party is jumping\n".to_string()));
    }

    #[test]
    fn challenge_five() {
        let filename = "input/set1_challenge5.txt";
        let ans = repeating_key_xor(filename, "ICE");
        let expected = "0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f".to_string();
        assert_eq!(ans, expected);
    }
}
