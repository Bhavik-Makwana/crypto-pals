use crate::set1::helper as set1_helper;
use rand::distributions::Alphanumeric;
use rand::{thread_rng, Rng};

pub fn detect_ecb(ciphertext: &str) -> bool {
    let bytes = base64::decode(&&ciphertext).unwrap();
    set1_helper::count_repeating_blocks(&bytes) > 0
}

pub fn detect_ecb_bytes(ciphertext: &Vec<u8>) -> bool {
    // let bytes = base64::decode(&&ciphertext).unwrap();
    set1_helper::count_repeating_blocks(&ciphertext) > 0
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
