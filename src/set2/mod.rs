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
    use crate::set1;

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
