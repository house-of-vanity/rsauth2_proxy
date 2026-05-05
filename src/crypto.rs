use aes_gcm::aead::{Aead, KeyInit};
use aes_gcm::{Aes256Gcm, Nonce};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use rand::RngCore;

#[derive(Clone)]
pub struct CookieCrypto {
    cipher: Aes256Gcm,
}

impl CookieCrypto {
    pub fn new(key_bytes: &[u8; 32]) -> Self {
        Self {
            cipher: Aes256Gcm::new_from_slice(key_bytes).expect("valid 32-byte key"),
        }
    }

    pub fn encrypt(&self, plaintext: &[u8]) -> anyhow::Result<String> {
        let mut nonce_bytes = [0u8; 12];
        rand::thread_rng().fill_bytes(&mut nonce_bytes);
        let nonce = Nonce::from_slice(&nonce_bytes);

        let ciphertext = self
            .cipher
            .encrypt(nonce, plaintext)
            .map_err(|e| anyhow::anyhow!("encryption failed: {}", e))?;

        let mut result = Vec::with_capacity(12 + ciphertext.len());
        result.extend_from_slice(&nonce_bytes);
        result.extend_from_slice(&ciphertext);

        Ok(URL_SAFE_NO_PAD.encode(&result))
    }

    pub fn decrypt(&self, encoded: &str) -> anyhow::Result<Vec<u8>> {
        let data = URL_SAFE_NO_PAD.decode(encoded)?;
        if data.len() < 13 {
            anyhow::bail!("ciphertext too short");
        }
        let (nonce_bytes, ciphertext) = data.split_at(12);
        let nonce = Nonce::from_slice(nonce_bytes);

        self.cipher
            .decrypt(nonce, ciphertext)
            .map_err(|e| anyhow::anyhow!("decryption failed: {}", e))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encrypt_decrypt_roundtrip() {
        let crypto = CookieCrypto::new(&[0x42; 32]);
        let plaintext = b"hello world";
        let encrypted = crypto.encrypt(plaintext).unwrap();
        let decrypted = crypto.decrypt(&encrypted).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn encrypt_produces_different_ciphertext_each_time() {
        let crypto = CookieCrypto::new(&[0x42; 32]);
        let a = crypto.encrypt(b"same").unwrap();
        let b = crypto.encrypt(b"same").unwrap();
        assert_ne!(a, b); // different nonces
    }

    #[test]
    fn wrong_key_fails() {
        let crypto1 = CookieCrypto::new(&[0x42; 32]);
        let crypto2 = CookieCrypto::new(&[0x43; 32]);
        let encrypted = crypto1.encrypt(b"hello").unwrap();
        assert!(crypto2.decrypt(&encrypted).is_err());
    }

    #[test]
    fn tampered_ciphertext_fails() {
        let crypto = CookieCrypto::new(&[0x42; 32]);
        let encrypted = crypto.encrypt(b"hello").unwrap();
        let mut data = URL_SAFE_NO_PAD.decode(&encrypted).unwrap();
        *data.last_mut().unwrap() ^= 0xFF;
        let tampered = URL_SAFE_NO_PAD.encode(&data);
        assert!(crypto.decrypt(&tampered).is_err());
    }

    #[test]
    fn empty_plaintext_roundtrip() {
        let crypto = CookieCrypto::new(&[0x42; 32]);
        let encrypted = crypto.encrypt(b"").unwrap();
        let decrypted = crypto.decrypt(&encrypted).unwrap();
        assert!(decrypted.is_empty());
    }

    #[test]
    fn short_ciphertext_rejected() {
        let crypto = CookieCrypto::new(&[0x42; 32]);
        assert!(crypto.decrypt("dG9vc2hvcnQ").is_err()); // "tooshort" base64
    }

    #[test]
    fn invalid_base64_rejected() {
        let crypto = CookieCrypto::new(&[0x42; 32]);
        assert!(crypto.decrypt("not valid base64!!!").is_err());
    }
}
