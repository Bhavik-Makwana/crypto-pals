extern crate aes;

use crate::errors::pkcs7_padding_error::Pkcs7PaddingError;
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

pub fn aes_ecb_encrypt_bytes(plaintext: &Vec<u8>, key: &str) -> Vec<u8> {
    let key_bytes = GenericArray::from_slice(key.as_bytes());

    let mut blocks = Vec::new();
    (0..plaintext.len()).step_by(16).for_each(|block_len| {
        blocks.push(GenericArray::clone_from_slice(
            &plaintext[block_len..block_len + 16],
        ))
    });
    let cipher = Aes128::new(&key_bytes);
    cipher.encrypt_blocks(&mut blocks);
    blocks.into_iter().flatten().collect::<Vec<u8>>()
}

pub fn aes_ecb_decrypt(ciphertext: &Vec<u8>, key: &str) -> String {
    let key_bytes = GenericArray::from_slice(key.as_bytes());

    let mut blocks = Vec::new();
    (0..ciphertext.len()).step_by(16).for_each(|block_len| {
        blocks.push(GenericArray::clone_from_slice(
            &ciphertext[block_len..block_len + 16],
        ))
    });
    let cipher = Aes128::new(&key_bytes);
    cipher.decrypt_blocks(&mut blocks);
    let flattened: Vec<_> = blocks.iter().flatten().cloned().collect();
    let unpadded = pkcs7_remove(&flattened, 16).unwrap();
    unpadded.iter().map(|&x| x as char).collect()
}

pub fn pkcs7(plaintext: &Vec<u8>, block_size: usize) -> Vec<u8> {
    let plaintext_len = plaintext.len();
    let padding_amount = block_size - plaintext_len % block_size;
    let padding: Vec<u8> = (0..padding_amount).map(|_| padding_amount as u8).collect();
    plaintext.iter().chain(padding.iter()).cloned().collect()
}

pub fn pkcs7_remove(
    padded_plaintext: &Vec<u8>,
    block_size: usize,
) -> Result<Vec<u8>, Pkcs7PaddingError> {
    if is_pkcs7_padded(padded_plaintext, block_size)? {
        let padding_amount = padded_plaintext.last().unwrap();
        return Ok(padded_plaintext[0..padded_plaintext.len() - *padding_amount as usize].to_vec());
    }
    Err(Pkcs7PaddingError::new("failed to remove padding"))
}

pub fn is_pkcs7_padded(plainbytes: &Vec<u8>, block_size: usize) -> Result<bool, Pkcs7PaddingError> {
    if plainbytes.len() % block_size != 0 {
        return Err(Pkcs7PaddingError::new("inconsistent message length"));
    }
    let last_char = plainbytes.last().unwrap();
    Ok(plainbytes
        .iter()
        .rev()
        .take(*last_char as usize)
        .all(|x| x == last_char))
}

pub fn aes128_cbc_encrypt(plaintext: &str, key: &str, iv_str: &str) -> String {
    let bytes = pkcs7(&plaintext.as_bytes().to_vec(), 16);
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

pub fn aes128_cbc_encrypt_bytes(plaintext: &Vec<u8>, key: &Vec<u8>, iv: &Vec<u8>) -> Vec<u8> {
    let bytes = pkcs7(plaintext, 16);
    let key_bytes = GenericArray::from_slice(key);
    let cipher = Aes128::new(&key_bytes);

    let mut blocks: Vec<Vec<u8>> = Vec::new();
    (0..bytes.len()).step_by(16).for_each(|idx| {
        let last = blocks.last().unwrap_or(&iv);

        let xor_block = xor_bytes(last, &bytes[idx..idx + 16]);
        let mut block = GenericArray::clone_from_slice(&xor_block);
        cipher.encrypt_block(&mut block);
        blocks.push(block.into_iter().collect::<Vec<u8>>());
    });
    blocks.into_iter().flatten().collect::<Vec<u8>>()
}

pub fn aes128_cbc_decrypt_bytes(cipherbytes: &Vec<u8>, key: &Vec<u8>, iv: &Vec<u8>) -> Vec<u8> {
    let key_bytes = GenericArray::from_slice(key);
    let cipher = Aes128::new(&key_bytes);

    let mut blocks: Vec<Vec<u8>> = Vec::new();
    (0..cipherbytes.len()).step_by(16).for_each(|idx| {
        let last = if idx == 0 {
            &iv
        } else {
            &cipherbytes[idx - 16..idx]
        };

        let mut block = GenericArray::clone_from_slice(&cipherbytes[idx..idx + 16]);
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
        .take(cipherbytes.len() - padding_byte)
        .collect::<Vec<u8>>()
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::set1;

    #[test]
    fn detects_pkcs7_padding() {
        let plaintext = "ICE ICE BABY\x04\x04\x04\x04";
        let bytes = plaintext.as_bytes().to_vec();
        assert_eq!(is_pkcs7_padded(&bytes, 16), Ok(true));
    }

    #[test]
    fn returns_false_if_not_pkcs7_padding() {
        let plaintext = "ICE ICE BABY\x05\x04\x04\x04";
        let bytes = plaintext.as_bytes().to_vec();
        assert_eq!(is_pkcs7_padded(&bytes, 16), Ok(false));
    }

    #[test]
    fn returns_error_if_message_length_inconsistent() {
        let plaintext = "ICE ICEY\x04\x04\x04\x04";
        let bytes = plaintext.as_bytes().to_vec();
        assert_eq!(
            is_pkcs7_padded(&bytes, 16),
            Err(Pkcs7PaddingError::new("inconsistent message length"))
        );
    }
}
