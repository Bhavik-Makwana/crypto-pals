use crate::set2::block_ciphers;
use std::collections::HashMap;
pub struct Profile {
    pub key: String,
}

impl Profile {
    pub fn new(&self, key: &str) -> Self {
        Profile {
            key: key.to_string(),
        }
    }

    pub fn encrypt_profile(&self, profile: &str) -> Vec<u8> {
        let padded = block_ciphers::pkcs7(&profile.as_bytes().to_vec(), 16);
        block_ciphers::aes_ecb_encrypt_bytes(&padded, &self.key)
    }

    pub fn decrypt_profile(&self, cipherbytes: Vec<u8>) -> HashMap<String, String> {
        let profile = block_ciphers::aes_ecb_decrypt(&cipherbytes, &self.key);
        Profile::kv_parser_raw(&profile)
    }

    pub fn profile_for(&self, email: &str) -> String {
        let sanitized_email: String = email.chars().filter(|c| *c != '&' && *c != '=').collect();
        format!("email={}&uid=10&role=user", sanitized_email)
    }

    pub fn kv_parser_raw(input: &str) -> HashMap<String, String> {
        input
            .split("&")
            .map(|pair| pair.split("=").collect::<Vec<_>>())
            .map(|v| (String::from(v[0]), String::from(v[1])))
            .collect()
    }
}
