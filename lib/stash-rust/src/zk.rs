//! Zero-knowledge encryption for client-side data protection.
//!
//! Uses AES-256-GCM with Argon2id key derivation for cross-SDK compatible encryption.

use crate::error::Error;
use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Nonce,
};
use argon2::{Algorithm, Argon2, Params, Version};
use base64::{engine::general_purpose::STANDARD, Engine};
use rand::RngCore;
use secrecy::{ExposeSecret, SecretString};
use zeroize::Zeroizing;

const ZK_PREFIX: &str = "$ZK$";
const ZK_SALT_SIZE: usize = 16;
const ZK_NONCE_SIZE: usize = 12; // aes-gcm standard nonce size
const ZK_KEY_SIZE: usize = 32; // aes-256
const ZK_MIN_KEY_LEN: usize = 16;
const ZK_MIN_DATA_SIZE: usize = ZK_SALT_SIZE + ZK_NONCE_SIZE + 16; // salt + nonce + gcm tag (minimum)

// argon2id parameters (must match other SDKs exactly)
const ARGON_TIME: u32 = 1;
const ARGON_MEMORY: u32 = 64 * 1024; // 64 MB
const ARGON_THREADS: u32 = 4;

/// checks if a value is ZK-encrypted by looking for the $ZK$ prefix
pub fn is_zk_encrypted(value: &str) -> bool {
    value.starts_with(ZK_PREFIX) && value.len() > ZK_PREFIX.len()
}

/// zero-knowledge crypto handler for client-side encryption
///
/// passphrase is stored securely using SecretString which zeroizes on drop
pub struct ZKCrypto {
    passphrase: SecretString,
}

impl Clone for ZKCrypto {
    fn clone(&self) -> Self {
        ZKCrypto {
            passphrase: SecretString::from(self.passphrase.expose_secret().to_owned()),
        }
    }
}

impl ZKCrypto {
    /// creates a new ZKCrypto instance with the given passphrase
    ///
    /// passphrase must be at least 16 characters
    pub fn new(passphrase: &str) -> Result<Self, Error> {
        if passphrase.len() < ZK_MIN_KEY_LEN {
            return Err(Error::InvalidParameter(
                "zk passphrase must be at least 16 characters".to_string(),
            ));
        }
        Ok(ZKCrypto {
            passphrase: SecretString::from(passphrase.to_string()),
        })
    }

    /// encrypts plaintext using AES-256-GCM with Argon2id key derivation
    ///
    /// format: $ZK$<base64(salt || nonce || ciphertext || tag)>
    pub fn encrypt(&self, plaintext: &[u8]) -> Result<String, Error> {
        // generate random salt
        let mut salt = [0u8; ZK_SALT_SIZE];
        rand::thread_rng().fill_bytes(&mut salt);

        // derive key using argon2id
        let key = self.derive_key(&salt)?;

        // create AES-GCM cipher
        let cipher = Aes256Gcm::new_from_slice(&key)
            .map_err(|e| Error::Decryption(format!("create cipher: {}", e)))?;

        // generate random nonce
        let mut nonce_bytes = [0u8; ZK_NONCE_SIZE];
        rand::thread_rng().fill_bytes(&mut nonce_bytes);
        let nonce = Nonce::from_slice(&nonce_bytes);

        // encrypt using GCM (includes authentication tag)
        let ciphertext = cipher
            .encrypt(nonce, plaintext)
            .map_err(|e| Error::Decryption(format!("encryption failed: {}", e)))?;

        // combine: salt || nonce || ciphertext (with tag appended)
        let mut combined = Vec::with_capacity(ZK_SALT_SIZE + ZK_NONCE_SIZE + ciphertext.len());
        combined.extend_from_slice(&salt);
        combined.extend_from_slice(&nonce_bytes);
        combined.extend_from_slice(&ciphertext);

        // encode as base64 with prefix
        let encoded = STANDARD.encode(&combined);
        Ok(format!("{}{}", ZK_PREFIX, encoded))
    }

    /// decrypts a ZK-encrypted value
    pub fn decrypt(&self, encrypted: &str) -> Result<Vec<u8>, Error> {
        // check and remove prefix
        if !is_zk_encrypted(encrypted) {
            return Err(Error::Decryption("missing $ZK$ prefix".to_string()));
        }
        let encoded = &encrypted[ZK_PREFIX.len()..];

        // decode base64
        let decoded = STANDARD
            .decode(encoded)
            .map_err(|e| Error::Decryption(format!("base64 decode: {}", e)))?;

        // check minimum size
        if decoded.len() < ZK_MIN_DATA_SIZE {
            return Err(Error::Decryption("encrypted data too short".to_string()));
        }

        // extract salt, nonce, ciphertext
        let salt = &decoded[..ZK_SALT_SIZE];
        let nonce_bytes = &decoded[ZK_SALT_SIZE..ZK_SALT_SIZE + ZK_NONCE_SIZE];
        let ciphertext = &decoded[ZK_SALT_SIZE + ZK_NONCE_SIZE..];

        // derive key using argon2id
        let key = self.derive_key(salt)?;

        // create AES-GCM cipher
        let cipher = Aes256Gcm::new_from_slice(&key)
            .map_err(|e| Error::Decryption(format!("create cipher: {}", e)))?;

        let nonce = Nonce::from_slice(nonce_bytes);

        // decrypt
        let plaintext = cipher.decrypt(nonce, ciphertext).map_err(|_| {
            Error::Decryption("decryption failed (wrong key or corrupted data)".to_string())
        })?;

        Ok(plaintext)
    }

    /// derives a 32-byte AES key from passphrase and salt using Argon2id
    ///
    /// returns the key wrapped in Zeroizing for automatic secure clearing
    fn derive_key(&self, salt: &[u8]) -> Result<Zeroizing<Vec<u8>>, Error> {
        let params = Params::new(ARGON_MEMORY, ARGON_TIME, ARGON_THREADS, Some(ZK_KEY_SIZE))
            .map_err(|e| Error::Decryption(format!("argon2 params: {}", e)))?;

        let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);

        let mut key = Zeroizing::new(vec![0u8; ZK_KEY_SIZE]);
        argon2
            .hash_password_into(self.passphrase.expose_secret().as_bytes(), salt, &mut key)
            .map_err(|e| Error::Decryption(format!("key derivation: {}", e)))?;

        Ok(key)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_is_zk_encrypted() {
        assert!(!is_zk_encrypted(""));
        assert!(!is_zk_encrypted("plain text"));
        assert!(!is_zk_encrypted("$ZK$"));
        assert!(is_zk_encrypted("$ZK$somedata"));
        assert!(!is_zk_encrypted("$zk$lowercase"));
    }

    #[test]
    fn test_new_validation() {
        // too short
        assert!(ZKCrypto::new("short").is_err());
        assert!(ZKCrypto::new("").is_err());

        // valid
        assert!(ZKCrypto::new("1234567890123456").is_ok());
        assert!(ZKCrypto::new("longer-passphrase-is-fine").is_ok());
    }

    #[test]
    fn test_encrypt_decrypt_round_trip() {
        let zk = ZKCrypto::new("test-passphrase-16").unwrap();

        let plaintexts = vec![
            b"hello world".to_vec(),
            b"".to_vec(),
            b"\x00\x01\x02\xff".to_vec(),
            "unicode: привет 🎉".as_bytes().to_vec(),
        ];

        for plaintext in plaintexts {
            let encrypted = zk.encrypt(&plaintext).unwrap();
            assert!(is_zk_encrypted(&encrypted));

            let decrypted = zk.decrypt(&encrypted).unwrap();
            assert_eq!(plaintext, decrypted);
        }
    }

    #[test]
    fn test_unique_encryptions() {
        let zk = ZKCrypto::new("test-passphrase-16").unwrap();
        let plaintext = b"same message";

        let enc1 = zk.encrypt(plaintext).unwrap();
        let enc2 = zk.encrypt(plaintext).unwrap();

        // should produce different ciphertexts (due to random salt/nonce)
        assert_ne!(enc1, enc2);

        // but both should decrypt to the same value
        let dec1 = zk.decrypt(&enc1).unwrap();
        let dec2 = zk.decrypt(&enc2).unwrap();
        assert_eq!(dec1, dec2);
        assert_eq!(plaintext.to_vec(), dec1);
    }

    #[test]
    fn test_wrong_key() {
        let zk1 = ZKCrypto::new("first-passphrase-16").unwrap();
        let zk2 = ZKCrypto::new("second-passphrase-16").unwrap();

        let plaintext = b"secret data";
        let encrypted = zk1.encrypt(plaintext).unwrap();

        // try to decrypt with wrong key
        assert!(zk2.decrypt(&encrypted).is_err());
    }

    #[test]
    fn test_invalid_data() {
        let zk = ZKCrypto::new("test-passphrase-16").unwrap();

        let invalid = vec![
            "notencrypted",
            "$ZK$",
            "$ZK$not-valid-base64!!!",
            "$ZK$YWJj", // valid base64 but too short
        ];

        for data in invalid {
            assert!(zk.decrypt(data).is_err());
        }
    }
}
