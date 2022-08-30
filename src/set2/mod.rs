extern crate aes;
pub mod block_ciphers;
pub mod helper;

use rand::{thread_rng, Rng};
use std::collections::HashMap;

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
    let secret_message_length = helper::identify_payload_length();
    let block_size = helper::identify_blocksize();
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

pub fn kv_parser_raw(input: &str) -> HashMap<String, String> {
    input
        .split("&")
        .map(|pair| pair.split("=").collect::<Vec<_>>())
        .map(|v| (String::from(v[0]), String::from(v[1])))
        .collect()
}

pub struct Profile {
    key: String,
}

impl Profile {
    pub fn new(&self, key: &str) -> Self {
        Profile {
            key: key.to_string(),
        }
    }

    pub fn encrypt_profile(&self, profile: &str) -> Vec<u8> {
        let padded = block_ciphers::pkcs7(&profile.as_bytes().to_vec(), 16);
        block_ciphers::aes_ecb_encrypt_bytes(&padded, &self.key)
    }

    pub fn decrypt_profile(&self, cipherbytes: Vec<u8>) -> HashMap<String, String> {
        let profile = block_ciphers::aes_ecb_decrypt(&cipherbytes, &self.key);
        kv_parser_raw(&profile)
    }

    pub fn profile_for(&self, email: &str) -> String {
        let sanitized_email: String = email.chars().filter(|c| *c != '&' && *c != '=').collect();
        format!("email={}&uid=10&role=user", sanitized_email)
    }
}

//challenge 13
pub fn cut_and_paste_ecb() -> Vec<u8> {
    let p = Profile {
        key: "YELLOW SUBMARINE".to_string(),
    };
    let block_size = 16;
    let malicious_email = "atck@mail.com";
    let malicious_profile = p.profile_for(&malicious_email);
    // block to modify
    let cipherbytes = p.encrypt_profile(&malicious_profile);
    let desired_role = "admin".as_bytes().to_vec();
    let payload = block_ciphers::pkcs7(&desired_role, block_size);

    let email = format!("foo@bar.co{}", String::from_utf8(payload).unwrap());
    let profile = p.profile_for(&email);
    let adminbytes = p.encrypt_profile(&profile);

    let malicious_block: Vec<u8> = adminbytes.iter().skip(16).take(16).cloned().collect();

    let manipulated_profile: Vec<u8> = cipherbytes
        .iter()
        .take(32)
        .chain(malicious_block.iter())
        .cloned()
        .collect();
    manipulated_profile
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::set1;

    #[test]
    fn challenge_thirteen() {
        let p = Profile {
            key: "YELLOW SUBMARINE".to_string(),
        };
        let res = cut_and_paste_ecb();
        let expected = "email=atck@mail.com&uid=10&role=user";
        let decrypted = p.decrypt_profile(res);
        assert_eq!(decrypted.get("role").unwrap(), "admin");
        assert_eq!(decrypted.get("email").unwrap(), "atck@mail.com");
        assert_eq!(decrypted.get("uid").unwrap(), "10");
    }

    #[test]
    fn profile_encrypts_decrypts_correctly() {
        let profile: String = "email=test@mail.com&uid=10&role=user".to_string();
        let key = helper::random_aes_key();
        let p = Profile { key };
        let parsed_profile = kv_parser_raw(&profile);
        let result = p.decrypt_profile(p.encrypt_profile(&profile));
        assert_eq!(parsed_profile, result);
    }

    #[test]
    fn creates_profile_correctly() {
        let key = helper::random_aes_key();
        let p = Profile { key };
        let email = "test@mail.com";
        let expected = "email=test@mail.com&uid=10&role=user";
        assert_eq!(p.profile_for(email), expected);
    }

    #[test]
    fn sanitizes_profile_correctly() {
        let p = Profile {
            key: "YELLOW SUBMARINE".to_string(),
        };
        let email = "tes&=t@mail.com";
        let expected = "email=test@mail.com&uid=10&role=user";
        assert_eq!(p.profile_for(email), expected);
    }

    #[test]
    fn parses_input_correctly() {
        let input = "foo=bar&baz=qux&zap=zazzle";
        let expected = HashMap::from([
            ("foo".to_string(), "bar".to_string()),
            ("baz".to_string(), "qux".to_string()),
            ("zap".to_string(), "zazzle".to_string()),
        ]);
        assert_eq!(kv_parser_raw(input), expected)
    }

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
