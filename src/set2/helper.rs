use crate::set1::helper as set1_helper;
use rand::distributions::Alphanumeric;
use rand::{thread_rng, Rng};

pub fn detect_ecb(ciphertext: &Vec<u8>) -> bool {
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

/*  --- Detect if ECB ---
    create 10 blocks of repeating characters (e.g. for 4 byte blocks create 10 'AAAA')
    if the blocks are all the same its ECB
*/
pub fn identify_if_ecb() -> bool {
    let res: f64 = (0..50)
            .map(|_| crate::set2::ecb_oracle(&"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".as_bytes().to_vec()))
            .map(|a| detect_ecb(&a))
            .filter(|x| *x == true)
            .count() as f64;
    if (res / 50.0) >= 0.8 {
        return true;
    }
    false
}
