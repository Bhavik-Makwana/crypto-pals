extern crate aes;

use crate::set1::aes_ecb;
use crate::set1::helper;
use crate::set2::aes::cipher::{BlockDecrypt, BlockEncrypt, KeyInit};
use aes::cipher::generic_array::GenericArray;
use aes::Aes128;

use rand::distributions::Alphanumeric;
use rand::{thread_rng, Rng};

pub fn pkcs7(plaintext: &str, block_size: usize) -> String {
    let plaintext_len = plaintext.len();
    let padding_amount = block_size - plaintext_len % block_size;
    let padding_char = padding_amount as u8 as char;
    let padding: String = (0..padding_amount).map(|_| padding_char).collect();
    format!("{}{}", plaintext, padding).to_string()
}

pub fn aes128_cbc_encrypt(plaintext: &str, key: &str, iv_str: &str) -> String {
    // let lines = io::read_file_no_newline(filename);
    let padded_msg = pkcs7(plaintext, 16);
    let bytes = padded_msg.as_bytes();
    let iv = iv_str.as_bytes().to_vec();

    let key_bytes = GenericArray::from_slice(key.as_bytes());
    let cipher = Aes128::new(&key_bytes);

    let mut blocks: Vec<Vec<u8>> = Vec::new();
    (0..bytes.len()).step_by(16).for_each(|idx| {
        let last = blocks.last().unwrap_or(&iv);

        let xor_block = xor_bytes(last, &bytes[idx..idx + 16]);
        let mut block = GenericArray::clone_from_slice(&xor_block);
        cipher.encrypt_block(&mut block);
        blocks.push(block.into_iter().collect::<Vec<u8>>());
    });
    hex::encode(blocks.into_iter().flatten().collect::<Vec<u8>>())
}

pub fn aes128_cbc_decrypt(ciphertext: &str, key: &str, iv_str: &str) -> String {
    let encrypted_bytes = hex::decode(ciphertext).unwrap();
    let key_bytes = GenericArray::from_slice(key.as_bytes());
    let iv = iv_str.as_bytes().to_vec();
    let cipher = Aes128::new(&key_bytes);

    let mut blocks: Vec<Vec<u8>> = Vec::new();
    (0..encrypted_bytes.len()).step_by(16).for_each(|idx| {
        let last = if idx == 0 {
            &iv
        } else {
            &encrypted_bytes[idx - 16..idx]
        };

        let mut block = GenericArray::clone_from_slice(&encrypted_bytes[idx..idx + 16]);
        cipher.decrypt_block(&mut block);
        let decrypted_block = block.into_iter().collect::<Vec<u8>>();

        // XOR decrypted block with last encrypted block to undo xor during encryption
        let xor_block = xor_bytes(last, &decrypted_block);
        blocks.push(xor_block);
    });
    let padding_byte = *blocks.last().unwrap().last().unwrap() as usize;
    blocks
        .into_iter()
        .flatten()
        .take(encrypted_bytes.len() - padding_byte)
        .map(|x| x as char)
        .collect::<String>()
}

pub fn xor_bytes(b1: &[u8], b2: &[u8]) -> Vec<u8> {
    b1.iter().zip(b2.iter()).map(|(x, y)| x ^ y).collect()
}

// challenge 11
pub fn ecryption_oracle(plaintext: &str) -> u8 {
    let key = "YELLOW SUBMARINE"; //random_aes_key();
    let padding = random_padding();

    // let padded_plaintext = format!("{}{}{}", padding, plaintext, padding);
    let padded_plaintext = format!("{}", plaintext);

    let mut rng = thread_rng();
    let choice = rng.gen_range(0..=1);
    let mut ciphertext;
    if choice == 0 {
        let iv: String = (0..16).map(|_| 0 as u8 as char).collect();
        ciphertext = aes128_cbc_encrypt(&padded_plaintext, &key, &iv);
        // ciphertext = aes_ecb_encrypt(&padded_plaintext, &key, false);
    } else {
        // println!("ECB expected");
        // let pkcs7_padding = pkcs7(&padded_plaintext, 16);
        // let send = &base64::encode(&padded_plaintext);
        // println!("{}", padded_plaintext);
        ciphertext = aes_ecb_encrypt(&padded_plaintext, &key, false);
        println!("{:?}", ciphertext);
    }
    if detect_ecb(&ciphertext) {
        println!("ECB");
        return 1;
    }
    println!("CBC");
    0
}
pub fn aes_ecb_encrypt(plaintext: &str, key: &str, is_base64: bool) -> String {
    let bytes;
    if is_base64 {
        bytes = base64::decode(plaintext).unwrap();
    } else {
        bytes = plaintext.as_bytes().to_vec();
    }
    println!("plaintext bytes {:?}", bytes);

    println!("LEN OF BYTES {}", bytes.len());
    let key_bytes = GenericArray::from_slice(key.as_bytes());

    let mut blocks = Vec::new();
    (0..bytes.len()).step_by(16).for_each(|block_len| {
        blocks.push(GenericArray::clone_from_slice(
            &bytes[block_len..block_len + 16],
        ))
    });
    println!("LEN OF BLOCKS {}", blocks[1].len());
    let cipher = Aes128::new(&key_bytes);
    cipher.encrypt_blocks(&mut blocks);

    base64::encode(blocks.into_iter().flatten().collect::<Vec<u8>>())
}

pub fn detect_ecb(ciphertext: &str) -> bool {
    let bytes = base64::decode(&&ciphertext).unwrap();
    let cnt = helper::count_repeating_blocks(&bytes);
    // println!("a {} b {}", ciphertext.len() / 16, cnt);
    cnt > 0
}

pub fn random_aes_key() -> String {
    thread_rng()
        .sample_iter(&Alphanumeric)
        .take(16)
        .map(char::from)
        .collect()
}

pub fn random_padding() -> String {
    let mut rng = thread_rng();
    thread_rng()
        .sample_iter(&Alphanumeric)
        .take(rng.gen_range(5..=10))
        .map(char::from)
        .collect()
}

// Challenge 12
// create an oracle
// pub fn aes128_ecb_oracle(filename: &str) -> String {
//     let key = "YELLOW SUBMARINE";
//     let lines = io::read_file_no_newline(filename);
//     let bytes = base64::decode(lines).unwrap();
//     let key_bytes = GenericArray::from_slice(key.as_bytes());

//     let mut blocks = Vec::new();
//     (0..bytes.len()).step_by(16).for_each(|block_len| {
//         blocks.push(GenericArray::clone_from_slice(
//             &bytes[block_len..block_len + 16],
//         ))
//     });
//     let cipher = Aes128::new(&key_bytes);
//     cipher.decrypt_blocks(&mut blocks);
//     blocks.iter().flatten().map(|&x| x as char).collect()
// }

/*  --- Detect block size ---
    feed n characters byte by byte into oracle until you get 2 blocks,
    n-1 is the block size length
*/

/*  --- Detect if ECB ---
    create 10 blocks of repeating characters (e.g. for 4 byte blocks create 10 'AAAA')
    if the blocks are all the same its ECB
*/

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
    #[test]
    fn challenge_nine() {
        let plaintext = "YELLOW SUBMARINE";
        let block_size = 20;
        assert_eq!(
            pkcs7(plaintext, block_size),
            "YELLOW SUBMARINE\x04\x04\x04\x04"
        )
    }

    #[test]
    fn challenge_ten() {
        let plaintext = "THIS IS A SUPER SECRET MESSAGE";
        let key = "MIKEY ISMIKEY IS";
        let iv: String = (0..16).map(|_| 0 as u8 as char).collect();
        let ciphertext = aes128_cbc_encrypt(plaintext, key, &iv);
        let decrypted_text = aes128_cbc_decrypt(&ciphertext, key, &iv);
        assert_eq!(plaintext, decrypted_text);
    }
}
