#![feature(test)]
extern crate base64;
extern crate hex;
extern crate test;
mod errors;
mod set1;
mod set2;

fn main() {
    // let ciphertext = hex::encode(
    //     base64::decode(set1::io::read_file_no_newline("input/set2_challenge10.txt")).unwrap(),
    // );
    // let key = "YELLOW SUBMARINE";
    // let iv: String = (0..16).map(|_| 0 as u8 as char).collect();
    // // let ciphertext = set2::aes128_cbc_encrypt(plaintext, key, &iv);
    // let decrypted_text = set2::aes128_cbc_decrypt(&ciphertext, key, &iv);
    // println!("msg: {:?}", decrypted_text);
    // set1::helper::count_repeating_blocks("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".as_bytes());
    let res = set2::break_ecb();
    // let pt = set2::block_ciphers::pkcs7_bytes("TEST".as_bytes().to_vec(), 16);
    // let res = set2::block_ciphers::aes_ecb_encrypt_bytes(&pt, "YELLOW SUBMARINE");
    println!("res: {}", res);
}
