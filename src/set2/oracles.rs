use crate::set2::block_ciphers;

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
