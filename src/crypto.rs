use base64::{Engine, engine::general_purpose::STANDARD};
use chacha20poly1305::{
    ChaCha20Poly1305, KeyInit, Nonce,
    aead::{Aead, Payload},
};
use rand::{RngCore, rngs::OsRng};

use crate::error::GradeError;

#[derive(Clone)]
pub struct Crypto {
    cipher: ChaCha20Poly1305,
}

impl Crypto {
    pub fn new(key: [u8; 32]) -> Self {
        Self {
            cipher: ChaCha20Poly1305::new_from_slice(&key).expect("32-byte key is valid"),
        }
    }

    pub fn random_master_key_base64() -> String {
        let mut key = [0_u8; 32];
        OsRng.fill_bytes(&mut key);
        STANDARD.encode(key)
    }

    pub fn encrypt(
        &self,
        field: &str,
        user_id: i64,
        plaintext: &str,
    ) -> Result<Vec<u8>, GradeError> {
        let mut nonce_bytes = [0_u8; 12];
        OsRng.fill_bytes(&mut nonce_bytes);
        let nonce = Nonce::from_slice(&nonce_bytes);
        let aad = aad(field, user_id);
        let ciphertext = self
            .cipher
            .encrypt(
                nonce,
                Payload {
                    msg: plaintext.as_bytes(),
                    aad: aad.as_bytes(),
                },
            )
            .map_err(|_| GradeError::Crypto("credential encryption failed".into()))?;

        let mut out = Vec::with_capacity(12 + ciphertext.len());
        out.extend_from_slice(&nonce_bytes);
        out.extend_from_slice(&ciphertext);
        Ok(out)
    }

    pub fn decrypt(&self, field: &str, user_id: i64, encoded: &[u8]) -> Result<String, GradeError> {
        if encoded.len() < 12 + 16 {
            return Err(GradeError::Decrypt("ciphertext is too short".into()));
        }
        let (nonce_bytes, ciphertext) = encoded.split_at(12);
        let aad = aad(field, user_id);
        let plaintext = self
            .cipher
            .decrypt(
                Nonce::from_slice(nonce_bytes),
                Payload {
                    msg: ciphertext,
                    aad: aad.as_bytes(),
                },
            )
            .map_err(|_| GradeError::Decrypt("credential decrypt failed".into()))?;
        String::from_utf8(plaintext)
            .map_err(|_| GradeError::Decrypt("decrypted credential is not UTF-8".into()))
    }
}

fn aad(field: &str, user_id: i64) -> String {
    format!("{field}:{user_id}")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn crypto() -> Crypto {
        Crypto::new([7_u8; 32])
    }

    #[test]
    fn round_trip_credential() {
        let encrypted = crypto().encrypt("uni_password", 42, "secret").unwrap();
        assert_ne!(encrypted, b"secret");
        assert_eq!(
            crypto().decrypt("uni_password", 42, &encrypted).unwrap(),
            "secret"
        );
    }

    #[test]
    fn tamper_fails() {
        let mut encrypted = crypto().encrypt("uni_password", 42, "secret").unwrap();
        let last = encrypted.len() - 1;
        encrypted[last] ^= 0x55;
        assert!(crypto().decrypt("uni_password", 42, &encrypted).is_err());
    }

    #[test]
    fn wrong_aad_fails() {
        let encrypted = crypto().encrypt("uni_password", 42, "secret").unwrap();
        assert!(crypto().decrypt("uni_password", 43, &encrypted).is_err());
    }
}
