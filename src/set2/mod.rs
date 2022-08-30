extern crate aes;
pub mod block_ciphers;
pub mod helper;
pub mod profile;
pub mod oracles;

use oracles::AesEcb128Oracle;
use profile::Profile;
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
pub fn encrypt(plaintext: &Vec<u8>) -> Vec<u8> {
    const KEY: &str = "YELLOW SUBMARINE";
    const PADDING_BASE64: &str = "Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkgaGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBqdXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUgYnkK";

    let padding = base64::decode(PADDING_BASE64).unwrap();
    let padded_plaintext = plaintext.iter().chain(padding.iter()).cloned().collect();
    let pkcs7_padding = block_ciphers::pkcs7(&padded_plaintext, 16);

    block_ciphers::aes_ecb_encrypt_bytes(&pkcs7_padding, &KEY)
}

fn break_ecb_byte(oracle: &AesEcb128Oracle, plaintext: &Vec<u8>, block_size: i32) -> Vec<u8> {
    let k = plaintext.len() as i32;
    let padding_length = (-k - 1).rem_euclid(block_size) as usize;
    let padding: Vec<u8> = (0..padding_length).map(|_| 'A' as u8).collect(); //vec![b"A"; padding_length];
                                                                             // println!("payload {}", padding);
    let target_block_num = (k / block_size) as usize;
    let cipherbytes = oracle.encrypt(&padding);
    let target_block = &cipherbytes
        [target_block_num * block_size as usize..(target_block_num + 1) * block_size as usize];
    for i in 0..=255 {
        let mut message: Vec<u8> = padding.iter().chain(plaintext.iter()).cloned().collect();
        message.push(i);
        let block = &oracle.encrypt(&message)
            [target_block_num * block_size as usize..(target_block_num + 1) * block_size as usize];
        if block == target_block {
            return vec![i];
        }
    }
    panic!("Failed");
}

pub fn break_ecb() -> String {
    let oracle = AesEcb128Oracle { 
        key: "YELLOW SUBMARINE".to_string(), 
        prefix: None, 
        target_bytes: "Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkgaGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBqdXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUgYnkK".as_bytes().to_vec()
    };

    let secret_message_length = helper::identify_payload_length(&oracle);
    let block_size = helper::identify_blocksize(&oracle);
    if !helper::identify_if_ecb(&oracle) {
        panic!("Not an ECB encrypted message")
    }
    let mut known_plaintext: Vec<u8> = "".to_string().as_bytes().to_vec();
    for _ in 0..secret_message_length {
        let new_byte = break_ecb_byte(&oracle, &known_plaintext, block_size as i32);
        known_plaintext = known_plaintext
            .iter()
            .chain(new_byte.iter())
            .cloned()
            .collect();
    }
    String::from_utf8_lossy(&known_plaintext).to_string()
}

//challenge 13
pub fn cut_and_paste_ecb(p: &Profile) -> Vec<u8> {
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



pub fn identify_prefix_size(oracle: &AesEcb128Oracle) -> usize {
    let mut plainbytes = vec!['A' as u8; 1];
    let mut curr: Vec<u8>;
    let mut prev = oracle
        .encrypt(&vec![])
        .iter()
        .take(16)
        .cloned()
        .collect();
    for i in 0..16 {
        curr = oracle
            .encrypt(&plainbytes)
            .iter()
            .take(16)
            .cloned()
            .collect();

        if curr == prev {
            return 16 - i;
        }
        prev = curr;
        plainbytes.push('A' as u8);
    }
    panic!("Did not find prefix");
}

// challenge 14

fn break_ecb_byte_prefix(
    oracle: &AesEcb128Oracle,
    plaintext: &Vec<u8>,
    block_size: i32,
    padding_size: i32,
) -> Vec<u8> {
    let k = plaintext.len() as i32;
    let padding_length = (-k - 1 - padding_size).rem_euclid(block_size) as usize;
    let target_block_num = ((k + padding_size) / block_size) as usize;
    let padding: Vec<u8> = (0..padding_length).map(|_| 'A' as u8).collect();
    let cipherbytes = oracle.encrypt(&padding);
    let target_block = &cipherbytes
        [target_block_num * block_size as usize..(target_block_num + 1) * block_size as usize];
    for i in 0..=255 {
        let mut message: Vec<u8> = padding.iter().chain(plaintext.iter()).cloned().collect();
        message.push(i);
        let block = &oracle.encrypt(&message)
            [target_block_num * block_size as usize..(target_block_num + 1) * block_size as usize];
        if block == target_block {
            return vec![i];
        }
    }
    panic!("Failed");
}

pub fn byte_at_a_time_ecb_decryption() -> String {
    let oracle = AesEcb128Oracle {
        key: "YELLOW SUBMARINE".to_string(),
        prefix: Some(helper::random_bytes()),
        target_bytes: "Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkgaGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBqdXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUgYnkK".as_bytes().to_vec(),
    };
    let secret_message_length = helper::identify_payload_length(&oracle);
    let block_size = helper::identify_blocksize(&oracle);
    let padding_size = identify_prefix_size(&oracle);
    if !helper::identify_if_ecb(&oracle) {
        panic!("Not an ECB encrypted message")
    }
    let mut known_plaintext: Vec<u8> = "".to_string().as_bytes().to_vec();
    for _ in 0..secret_message_length {
        let new_byte = break_ecb_byte_prefix(
            &oracle,
            &known_plaintext,
            block_size as i32,
            padding_size as i32,
        );
        known_plaintext = known_plaintext
            .iter()
            .chain(new_byte.iter())
            .cloned()
            .collect();
        println!("{}", String::from_utf8_lossy(&known_plaintext).to_string());
    }
    String::from_utf8_lossy(&known_plaintext).to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::set1;

    #[test]
    fn challenge_fourteen() {
        assert_eq!(
            byte_at_a_time_ecb_decryption(),
            "Rollin' in my 5.0\
        \nWith my rag-top down so my hair can blow\
        \nThe girlies on standby waving just to say hi\
        \nDid you stop? No, I just drove by\
        \n\u{1}"
        );
    }

    #[test]
    fn challenge_thirteen() {
        let p = Profile {
            key: "YELLOW SUBMARINE".to_string(),
        };
        let res = cut_and_paste_ecb(&p);
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
        let parsed_profile = Profile::kv_parser_raw(&profile);
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
        let p = Profile {
            key: "YELLOW SUBMARINE".to_string(),
        };
        let input = "foo=bar&baz=qux&zap=zazzle";
        let expected = HashMap::from([
            ("foo".to_string(), "bar".to_string()),
            ("baz".to_string(), "qux".to_string()),
            ("zap".to_string(), "zazzle".to_string()),
        ]);
        assert_eq!(Profile::kv_parser_raw(input), expected)
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
