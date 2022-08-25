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
    let res = (0..50)
        .map(|_| set2::ecryption_oracle("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"))
        .filter(|x| *x == 1)
        .count();
    println!("res: {}", res);
}
