use crate::set1::helper as set1_helper;
use crate::set2::oracles::AesEcb128Oracle;
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

pub fn random_bytes() -> Vec<u8> {
    let mut rng = thread_rng();
    thread_rng()
        .sample_iter(&Alphanumeric)
        .take(rng.gen_range(0..=15))
        .collect()
}

/*  --- Detect if ECB ---
    create 10 blocks of repeating characters (e.g. for 4 byte blocks create 10 'AAAA')
    if the blocks are all the same its ECB
*/
pub fn identify_if_ecb(oracle: &AesEcb128Oracle) -> bool {
    let res: f64 = (0..50)
            .map(|_| oracle.ecb_oracle_no_prefix(&"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".as_bytes().to_vec()))
            .map(|a| detect_ecb(&a))
            .filter(|x| *x == true)
            .count() as f64;
    if (res / 50.0) >= 0.8 {
        return true;
    }
    false
}

/*  --- Detect block size ---
    feed n characters byte by byte into oracle until you get 2 blocks,
    n-1 is the block size length
*/
pub fn identify_blocksize(oracle: &AesEcb128Oracle) -> usize {
    let mut input: Vec<u8> = vec!['A' as u8; 1];
    let mut curr;
    let mut prev = oracle.ecb_oracle_no_prefix(&input);
    loop {
        input.push('A' as u8);
        curr = oracle.ecb_oracle_no_prefix(&input);
        if curr[0..4] == prev[0..4] {
            break;
        }
        prev = curr;
    }
    input.len() - 1
}

pub fn identify_payload_length(oracle: &AesEcb128Oracle) -> usize {
    let previous_length = oracle.ecb_oracle_no_prefix(&"".as_bytes().to_vec()).len();
    let mut i = 0;
    let mut input = vec!['A' as u8; 1];
    loop {
        let length = oracle.ecb_oracle_no_prefix(&input).len();
        input.push('A' as u8);
        if length != previous_length {
            return previous_length - i;
        }
        i += 1;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn identify_if_ecb_encryption() {
        let oracle = AesEcb128Oracle {
            key: "YELLOW SUBMARINE".to_string(),
            prefix: None,
            target_bytes: "Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkgaGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBqdXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUgYnkK".as_bytes().to_vec(),
        };
        assert_eq!(identify_if_ecb(&oracle), true);
    }

    #[test]
    fn identify_length_of_payload() {
        let oracle = AesEcb128Oracle {
            key: "YELLOW SUBMARINE".to_string(),
            prefix: None,
            target_bytes: "Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkgaGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBqdXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUgYnkK".as_bytes().to_vec(),
        };
        assert_eq!(identify_payload_length(&oracle), 139);
    }

    #[test]
    fn identify_the_blocksize() {
        let oracle = AesEcb128Oracle {
            key: "YELLOW SUBMARINE".to_string(),
            prefix: None,
            target_bytes: "Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkgaGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBqdXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUgYnkK".as_bytes().to_vec(),
        };
        assert_eq!(identify_blocksize(&oracle), 16);
    }
}
