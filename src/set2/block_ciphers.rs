extern crate aes;

use crate::set2::aes::cipher::{BlockDecrypt, BlockEncrypt, KeyInit};
use aes::cipher::generic_array::GenericArray;
use aes::Aes128;

pub fn aes_ecb_encrypt(plaintext: &str, key: &str, is_base64: bool) -> String {
    let bytes;
    if is_base64 {
        bytes = base64::decode(plaintext).unwrap();
    } else {
        bytes = plaintext.as_bytes().to_vec();
    }
    let key_bytes = GenericArray::from_slice(key.as_bytes());

    let mut blocks = Vec::new();
    (0..bytes.len()).step_by(16).for_each(|block_len| {
        blocks.push(GenericArray::clone_from_slice(
            &bytes[block_len..block_len + 16],
        ))
    });
    let cipher = Aes128::new(&key_bytes);
    cipher.encrypt_blocks(&mut blocks);

    base64::encode(blocks.into_iter().flatten().collect::<Vec<u8>>())
}

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
