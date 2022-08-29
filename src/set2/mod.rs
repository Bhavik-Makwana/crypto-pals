extern crate aes;
pub mod block_ciphers;
pub mod helper;

use crate::set1::aes_ecb_decrypt;
use crate::set2::aes::cipher::{BlockDecrypt, BlockEncrypt, KeyInit};
use aes::cipher::generic_array::GenericArray;
use aes::Aes128;

use rand::distributions::Alphanumeric;
use rand::{thread_rng, Rng};

#[derive(PartialEq)]
pub enum AesBlockMode {
    ECB,
    CBC,
}

// challenge 11
pub fn ecryption_oracle(plaintext: &str) -> AesBlockMode {
    let key = helper::random_aes_key();
    let padding = helper::random_padding();

    let padded_plaintext = format!("{}{}{}", padding, plaintext, padding);

    let mut rng = thread_rng();
    let choice = rng.gen_range(0..=1);
    let mut ciphertext;
    if choice == 0 {
        let iv: String = (0..16).map(|_| 0 as u8 as char).collect();
        ciphertext = block_ciphers::aes128_cbc_encrypt(&padded_plaintext, &key, &iv);
    } else {
        let pkcs7_padding = block_ciphers::pkcs7(&padded_plaintext, 16);
        ciphertext = block_ciphers::aes_ecb_encrypt(&pkcs7_padding, &key, false);
    }
    if helper::detect_ecb(&ciphertext) {
        return AesBlockMode::ECB;
    }
    AesBlockMode::CBC
}

// Challenge 12
// create an oracle
pub fn ecb_oracle(plaintext: &str) -> String {
    let key = "YELLOW SUBMARINE";
    let pkcs7_padding = block_ciphers::pkcs7(&plaintext, 16);

    block_ciphers::aes_ecb_encrypt(&pkcs7_padding, &key, false)
}

pub fn ecb_oracle_padded(plaintext: &str) -> String {
    let key = "YELLOW SUBMARINE";
    // let padding_base64 = "Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkgaGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBqdXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUgYnkK"
    // .to_string();
    let padding_base64 = "cGVsYXNlIHdvcmsgd3RmIGlzIGdvaW5nIHdyb25nIGFoaGFwZWxhc2Ugd29yayB3dGYgaXMgZ29pbmcgd3JvbmcgYWhoYQ==".to_string();
    let padding: String = base64::decode(padding_base64)
        .unwrap()
        .iter()
        .map(|c| *c as u8 as char)
        .collect();

    let padded_plaintext = format!("{}{}", plaintext, padding);
    let pkcs7_padding = block_ciphers::pkcs7(&padded_plaintext, 16);

    block_ciphers::aes_ecb_encrypt(&pkcs7_padding, &key, false)
}

/*  --- Detect block size ---
    feed n characters byte by byte into oracle until you get 2 blocks,
    n-1 is the block size length
*/
pub fn identify_blocksize() -> usize {
    let mut input = "A".to_string();
    let mut curr = ecb_oracle_padded(&input);
    let mut prev = ecb_oracle_padded(&input);
    loop {
        input.push_str("A");
        curr = ecb_oracle(&input);
        if (curr[0..4] == prev[0..4]) {
            break;
        }
        prev = curr;
    }
    input.len() - 1
}

/*  --- Detect if ECB ---
    create 10 blocks of repeating characters (e.g. for 4 byte blocks create 10 'AAAA')
    if the blocks are all the same its ECB
*/
fn identify_if_ecb() -> bool {
    let res: f64 = (0..50)
            .map(|_| ecb_oracle("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"))
            .map(|a| helper::detect_ecb(&a))
            .filter(|x| *x == true)
            .count() as f64;
    if ((res / 50.0) >= 0.8) {
        return true;
    }
    false
}

fn identify_payload_length() -> usize {
    let previous_length = ecb_oracle_padded("").len();
    let mut i = 0;
    let mut input = "A".to_string();
    loop {
        let length = ecb_oracle_padded(&input).len();
        input.push_str("A");
        if length != previous_length {
            break;
        }
        i += 1;
    }
    return previous_length - (i + 1);
}

fn break_ecb_byte(plaintext: &str, block_size: i32) -> char {
    let k = plaintext.len() as i32;
    let attack_payload_size = (-k - 1).rem_euclid(block_size) as usize;
    println!("payload size {}", attack_payload_size);
    let mut attack_payload: String = (0..attack_payload_size).map(|_| "A").collect();
    println!("payload {}", attack_payload);
    let target_block_num = (k / block_size) as usize;
    let mut ciphertext = ecb_oracle_padded(&attack_payload);
    let target_block = &ciphertext
        [target_block_num * block_size as usize..(target_block_num + 1) * block_size as usize];
    println!("{}={}/{}", target_block_num, k, block_size);
    for i in 0..128 {
        let message = format!("{}{}{}", attack_payload, plaintext, i as u8 as char);
        println!(
            "i {} {}",
            i,
            &message[target_block_num * block_size as usize
                ..(target_block_num + 1) * block_size as usize]
        );
        println!(
            "SLICE: [{}..{}]",
            target_block_num * block_size as usize,
            (target_block_num + 1) * block_size as usize
        );
        let block = &ecb_oracle_padded(&message)
            [target_block_num * block_size as usize..(target_block_num + 1) * block_size as usize];
        if block == target_block {
            println!(
                "target: {} \ncurr:{}   char {}: {}\n pt: {}",
                target_block, block, i, i as u8 as char, plaintext
            );
            println!("MATCHINGMATCHING");
            return i as u8 as char;
        }
        // if i as u8 as char == 'r' {

        println!(
            "idx: {} block: {} pt: {}{}",
            i, target_block_num, plaintext, i as u8 as char
        );
    }
    panic!("Failed");
}

pub fn break_ecb() -> String {
    // let secret_message_length = identify_payload_length();
    let secret_message_length = "cGVsYXNlIHdvcmsgd3RmIGlzIGdvaW5nIHdyb25nIGFoaGFwZWxhc2Ugd29yayB3dGYgaXMgZ29pbmcgd3JvbmcgYWhoYQ=="
        .to_string()
        .chars()
        .count();
    let block_size = 16; //identify_blocksize();
    println!(
        "msg len {} block size {}",
        secret_message_length, block_size
    );
    let mut known_plaintext = "".to_string();
    for _ in 0..secret_message_length {
        let new_byte = break_ecb_byte(&known_plaintext, block_size as i32);
        known_plaintext = format!("{}{}", known_plaintext, new_byte);
        println!("{}", known_plaintext);
    }
    known_plaintext
}
// fn build_dictionary(input: &str) -> HashSet<String> {}
/*  --- Create dictionary ---
    create a dictionary of every possible last byte by feeding different strings to oracle
    where the strings are your input string of length unknown string-1 with changing last character
    when you aes encrypt the text with that string of unknown string-1 and the unknown string you
    will be able to detect what the first character is

    repeat until decrypted

    shorten the input string each time and build dictionary up until you detect the first block

*/

#[cfg(test)]
mod tests {
    use super::*;
    use crate::set1;

    #[test]
    fn identify_if_ecb_encryption() {
        assert_eq!(identify_if_ecb(), true);
    }

    #[test]
    fn identify_length_of_payload() {
        assert_eq!(identify_payload_length(), 192);
    }

    #[test]
    fn identify_the_blocksize() {
        assert_eq!(identify_blocksize(), 16);
    }

    #[test]
    fn challenge_eleven() {
        let mut total = 0;
        for i in 0..10 {
            let res = (0..50)
            .map(|_| ecryption_oracle("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"))
            .filter(|x| *x == AesBlockMode::ECB)
            .count();
            total += res;
        }
        let avg = total / 10;
        let range = 23..28;
        assert!(range.contains(&avg));
    }

    #[test]
    fn aes_ecb() {
        let ptxt = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
        let ctxt = block_ciphers::aes_ecb_encrypt(ptxt, "YELLOW SUBMARINE", false);
        let res = set1::aes_ecb_decrypt(&ctxt, "YELLOW SUBMARINE", true);
        assert_eq!(res, "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA");
    }

    #[test]
    fn challenge_nine() {
        let plaintext = "YELLOW SUBMARINE";
        let block_size = 20;
        assert_eq!(
            block_ciphers::pkcs7(plaintext, block_size),
            "YELLOW SUBMARINE\x04\x04\x04\x04"
        )
    }

    #[test]
    fn challenge_ten() {
        let plaintext = "THIS IS A SUPER SECRET MESSAGE";
        let key = "MIKEY ISMIKEY IS";
        let iv: String = (0..16).map(|_| 0 as u8 as char).collect();
        let ciphertext = block_ciphers::aes128_cbc_encrypt(plaintext, key, &iv);
        let decrypted_text = block_ciphers::aes128_cbc_decrypt(&ciphertext, key, &iv);
        assert_eq!(plaintext, decrypted_text);
    }
}
