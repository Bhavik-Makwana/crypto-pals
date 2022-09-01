use crate::set2::block_ciphers;
use crate::set2::helper;
extern crate url_escape;
pub struct AesCbc128Oracle {
    pub key: Vec<u8>,
    pub prefix: Vec<u8>,
    pub suffix: Vec<u8>,
    pub iv: Vec<u8>,
}

impl AesCbc128Oracle {
    fn escape_input(&self, plaintext: &str) -> String {
        let mut escaped_plaintext = plaintext.replace(";", "%3D");
        escaped_plaintext = escaped_plaintext.replace("=", "%3E");
        escaped_plaintext
    }

    pub fn encrypt(&self, plaintext: &str) -> Vec<u8> {
        let escaped_plaintext = self.escape_input(plaintext);
        let bytes = escaped_plaintext.as_bytes().to_vec();
        let message: Vec<u8> = self
            .prefix
            .iter()
            .chain(bytes.iter())
            .chain(self.suffix.iter())
            .cloned()
            .collect();
        println!("message {} \n END", String::from_utf8_lossy(&message));
        block_ciphers::aes128_cbc_encrypt_bytes(&message, &self.key, &self.iv)
    }

    pub fn decrypt_and_check_admin(&self, ciphertext: &Vec<u8>) -> bool {
        let plainbytes = block_ciphers::aes128_cbc_decrypt_bytes(ciphertext, &self.key, &self.iv);
        println!("bytes {}", String::from_utf8_lossy(&plainbytes));
        self.is_sub(&plainbytes, ";admin=true".as_bytes())
    }

    pub fn decrypt(&self, ciphertext: &Vec<u8>) -> Vec<u8> {
        block_ciphers::aes128_cbc_decrypt_bytes(ciphertext, &self.key, &self.iv)
    }

    fn is_sub<T: PartialEq>(&self, haystack: &[T], needle: &[T]) -> bool {
        haystack.windows(needle.len()).any(|c| c == needle)
    }
}

pub struct AesEcb128Oracle {
    pub key: String,
    pub prefix: Option<Vec<u8>>,
    pub target_bytes: Vec<u8>,
}

impl AesEcb128Oracle {
    pub fn encrypt(&self, plaintext: &Vec<u8>) -> Vec<u8> {
        if let Some(_) = self.prefix {
            return self.ecb_oracle_with_prefix(plaintext);
        } else {
            return self.ecb_oracle_no_prefix(plaintext);
        }
    }

    fn ecb_oracle_with_prefix(&self, plaintext: &Vec<u8>) -> Vec<u8> {
        let padding = base64::decode(self.target_bytes.clone()).unwrap();
        let padded_plaintext = self
            .prefix
            .as_ref()
            .unwrap()
            .iter()
            .chain(plaintext.iter())
            .chain(padding.iter())
            .cloned()
            .collect();
        let pkcs7_padding = block_ciphers::pkcs7(&padded_plaintext, 16);
        block_ciphers::aes_ecb_encrypt_bytes(&pkcs7_padding, &self.key)
    }

    pub fn ecb_oracle_no_prefix(&self, plaintext: &Vec<u8>) -> Vec<u8> {
        let padding = base64::decode(self.target_bytes.clone()).unwrap();
        let padded_plaintext = plaintext.iter().chain(padding.iter()).cloned().collect();
        let pkcs7_padding = block_ciphers::pkcs7(&padded_plaintext, 16);
        block_ciphers::aes_ecb_encrypt_bytes(&pkcs7_padding, &self.key)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::set1;

    #[test]
    fn cbc_oracle_works() {
        let oracle = AesCbc128Oracle {
            key: helper::random_aes_key().as_bytes().to_vec(),
            iv: helper::random_iv(),
            prefix: "comment1=cooking%20MCs;userdata=".as_bytes().to_vec(),
            suffix: ";comment2=%20like%20a%20pound%20of%20bacon"
                .as_bytes()
                .to_vec(),
        };
        let input = ";admin=true";
        let ciphertext = oracle.encrypt(&input);
        assert_eq!(oracle.decrypt_and_check_admin(&ciphertext), false);
    }
}
