extern crate aes;
pub mod block_ciphers;
pub mod helper;

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
    let ciphertext;
    if choice == 0 {
        let iv: String = (0..16).map(|_| 0 as u8 as char).collect();
        ciphertext = block_ciphers::aes128_cbc_encrypt(&padded_plaintext, &key, &iv)
            .as_bytes()
            .to_vec();
    } else {
        let pkcs7_padding = block_ciphers::pkcs7(&padded_plaintext.as_bytes().to_vec(), 16);
        ciphertext = block_ciphers::aes_ecb_encrypt_bytes(&pkcs7_padding, &key);
    }
    if helper::detect_ecb(&ciphertext) {
        return AesBlockMode::ECB;
    }
    AesBlockMode::CBC
}

// Challenge 12
// create an oracle
pub fn ecb_oracle(plaintext: &Vec<u8>) -> Vec<u8> {
    const KEY: &str = "YELLOW SUBMARINE";
    const PADDING_BASE64: &str = "Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkgaGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBqdXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUgYnkK";

    let padding = base64::decode(PADDING_BASE64).unwrap();
    let padded_plaintext = plaintext.iter().chain(padding.iter()).cloned().collect();
    let pkcs7_padding = block_ciphers::pkcs7(&padded_plaintext, 16);

    block_ciphers::aes_ecb_encrypt_bytes(&pkcs7_padding, &KEY)
}

/*  --- Detect block size ---
    feed n characters byte by byte into oracle until you get 2 blocks,
    n-1 is the block size length
*/
pub fn identify_blocksize() -> usize {
    let mut input: Vec<u8> = vec!['A' as u8; 1];
    let mut curr;
    let mut prev = ecb_oracle(&input);
    loop {
        input.push('A' as u8);
        curr = ecb_oracle(&input);
        if curr[0..4] == prev[0..4] {
            break;
        }
        prev = curr;
    }
    input.len() - 1
}

fn identify_payload_length() -> usize {
    let previous_length = ecb_oracle(&"".as_bytes().to_vec()).len();
    let mut i = 0;
    let mut input = vec!['A' as u8; 1];
    loop {
        let length = ecb_oracle(&input).len();
        input.push('A' as u8);
        if length != previous_length {
            return previous_length - i;
        }
        i += 1;
    }
}

fn break_ecb_byte(plaintext: &Vec<u8>, block_size: i32) -> Vec<u8> {
    let k = plaintext.len() as i32;
    let padding_length = (-k - 1).rem_euclid(block_size) as usize;
    let padding: Vec<u8> = (0..padding_length).map(|_| 'A' as u8).collect(); //vec![b"A"; padding_length];
                                                                             // println!("payload {}", padding);
    let target_block_num = (k / block_size) as usize;
    let cipherbytes = ecb_oracle(&padding);
    let target_block = &cipherbytes
        [target_block_num * block_size as usize..(target_block_num + 1) * block_size as usize];
    for i in 0..=255 {
        let mut message: Vec<u8> = padding.iter().chain(plaintext.iter()).cloned().collect();
        message.push(i);
        let block = &ecb_oracle(&message)
            [target_block_num * block_size as usize..(target_block_num + 1) * block_size as usize];
        if block == target_block {
            return vec![i];
        }
    }
    panic!("Failed");
}

pub fn break_ecb() -> String {
    let secret_message_length = identify_payload_length();
    let block_size = identify_blocksize();
    if !helper::identify_if_ecb() {
        panic!("Not an ECB encrypted message")
    }
    let mut known_plaintext: Vec<u8> = "".to_string().as_bytes().to_vec();
    for _ in 0..secret_message_length {
        let new_byte = break_ecb_byte(&known_plaintext, block_size as i32);
        known_plaintext = known_plaintext
            .iter()
            .chain(new_byte.iter())
            .cloned()
            .collect();
    }
    String::from_utf8_lossy(&known_plaintext).to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::set1;

    #[test]
    fn challenge_twelve() {
        assert_eq!(
            break_ecb(),
            "Rollin' in my 5.0\
        \nWith my rag-top down so my hair can blow\
        \nThe girlies on standby waving just to say hi\
        \nDid you stop? No, I just drove by\
        \n\u{1}"
        );
    }

    #[test]
    fn identify_if_ecb_encryption() {
        assert_eq!(helper::identify_if_ecb(), true);
    }

    #[test]
    fn identify_length_of_payload() {
        assert_eq!(identify_payload_length(), 139);
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
        let plaintext = "YELLOW SUBMARINE".as_bytes().to_vec();
        let block_size = 20;
        assert_eq!(
            block_ciphers::pkcs7(&plaintext, block_size),
            "YELLOW SUBMARINE\x04\x04\x04\x04".as_bytes().to_vec()
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
