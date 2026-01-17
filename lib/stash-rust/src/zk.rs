use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Nonce,
};
use argon2::Argon2;
use base64::{engine::general_purpose::STANDARD as BASE64, Engine};
use rand::RngCore;
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::error::Error;

const ZK_PREFIX: &str = "$ZK$";
const ZK_SALT_SIZE: usize = 16;
const ZK_NONCE_SIZE: usize = 12;
const ZK_KEY_SIZE: usize = 32;
const ZK_MIN_KEY_LEN: usize = 16;
const ZK_MIN_DATA_SIZE: usize = ZK_SALT_SIZE + ZK_NONCE_SIZE + 16; // salt + nonce + tag

// argon2id parameters (must match other SDKs)
const ARGON_TIME: u32 = 1;
const ARGON_MEMORY: u32 = 64 * 1024; // 64 MB
const ARGON_THREADS: u32 = 4;

/// Checks if a value is ZK-encrypted.
///
/// ZK-encrypted values start with the prefix `$ZK$`.
///
/// # Examples
///
/// ```
/// use stash::zk::is_zk_encrypted;
///
/// assert!(is_zk_encrypted("$ZK$base64data..."));
/// assert!(!is_zk_encrypted("regular-value"));
/// ```
pub fn is_zk_encrypted(value: &str) -> bool {
    value.starts_with(ZK_PREFIX)
}

/// Zero-knowledge encryption handler using AES-256-GCM with Argon2id key derivation.
///
/// The `ZKCrypto` struct provides client-side encryption with secure memory handling.
/// The passphrase is zeroized when dropped to prevent memory leaks.
///
/// Encrypted format: `$ZK$<base64(salt[16] || nonce[12] || ciphertext || tag[16])>`
///
/// Argon2id parameters (cross-SDK compatible):
/// - Time cost: 1
/// - Memory cost: 65536 (64 MB)
/// - Parallelism: 4
/// - Output length: 32 bytes
///
/// # Examples
///
/// ```
/// # #[cfg(feature = "zk")]
/// # {
/// use stash::zk::ZKCrypto;
///
/// let zk = ZKCrypto::new("my-passphrase-min-16-chars").unwrap();
///
/// // encrypt data
/// let encrypted = zk.encrypt(b"secret data").unwrap();
/// println!("Encrypted: {}", encrypted);
///
/// // decrypt data
/// let decrypted = zk.decrypt(&encrypted).unwrap();
/// assert_eq!(decrypted, b"secret data");
/// # }
/// ```
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct ZKCrypto {
    passphrase: String,
}

impl ZKCrypto {
    /// Creates a new `ZKCrypto` instance with the given passphrase.
    ///
    /// # Arguments
    ///
    /// * `passphrase` - The passphrase for encryption/decryption (minimum 16 characters)
    ///
    /// # Errors
    ///
    /// Returns an error if the passphrase is less than 16 characters.
    ///
    /// # Examples
    ///
    /// ```
    /// # #[cfg(feature = "zk")]
    /// # {
    /// # fn example() -> Result<(), stash::Error> {
    /// use stash::zk::ZKCrypto;
    ///
    /// let zk = ZKCrypto::new("my-passphrase-min-16-chars")?;
    /// # Ok(())
    /// # }
    /// # }
    /// ```
    pub fn new(passphrase: &str) -> Result<Self, Error> {
        if passphrase.len() < ZK_MIN_KEY_LEN {
            return Err(Error::Connection(
                "passphrase must be at least 16 characters".to_string(),
            ));
        }
        Ok(Self {
            passphrase: passphrase.to_string(),
        })
    }

    /// Encrypts plaintext using AES-256-GCM with Argon2id key derivation.
    ///
    /// Each encryption uses a fresh random salt and nonce, so encrypting the same
    /// plaintext twice produces different ciphertexts.
    ///
    /// Format: `$ZK$<base64(salt[16] || nonce[12] || ciphertext || tag[16])>`
    ///
    /// # Arguments
    ///
    /// * `plaintext` - The data to encrypt
    ///
    /// # Errors
    ///
    /// Returns an error if encryption fails (rare).
    ///
    /// # Examples
    ///
    /// ```
    /// # #[cfg(feature = "zk")]
    /// # {
    /// # fn example() -> Result<(), stash::Error> {
    /// use stash::zk::ZKCrypto;
    ///
    /// let zk = ZKCrypto::new("my-passphrase-min-16-chars")?;
    /// let encrypted = zk.encrypt(b"secret data")?;
    /// assert!(encrypted.starts_with("$ZK$"));
    /// # Ok(())
    /// # }
    /// # }
    /// ```
    pub fn encrypt(&self, plaintext: &[u8]) -> Result<String, Error> {
        // generate random salt
        let mut salt = [0u8; ZK_SALT_SIZE];
        rand::thread_rng().fill_bytes(&mut salt);

        // derive key using argon2id
        let key = self.derive_key(&salt);

        // create cipher
        let cipher = Aes256Gcm::new_from_slice(&key)
            .map_err(|e| Error::Connection(format!("create cipher: {}", e)))?;

        // generate random nonce
        let mut nonce_bytes = [0u8; ZK_NONCE_SIZE];
        rand::thread_rng().fill_bytes(&mut nonce_bytes);
        let nonce = Nonce::from_slice(&nonce_bytes);

        // encrypt using GCM (includes authentication tag)
        let ciphertext = cipher
            .encrypt(nonce, plaintext)
            .map_err(|e| Error::Connection(format!("encryption failed: {}", e)))?;

        // combine: salt || nonce || ciphertext (with tag appended)
        let mut combined = Vec::with_capacity(ZK_SALT_SIZE + ZK_NONCE_SIZE + ciphertext.len());
        combined.extend_from_slice(&salt);
        combined.extend_from_slice(&nonce_bytes);
        combined.extend_from_slice(&ciphertext);

        // encode as base64 with prefix
        let encoded = BASE64.encode(&combined);
        Ok(format!("{}{}", ZK_PREFIX, encoded))
    }

    /// Decrypts a ZK-encrypted value.
    ///
    /// # Arguments
    ///
    /// * `encrypted` - The encrypted value (must start with `$ZK$`)
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The value doesn't start with `$ZK$`
    /// - The base64 encoding is invalid
    /// - The data is too short (corrupted)
    /// - The passphrase is incorrect
    /// - The authentication tag verification fails (data was tampered with)
    ///
    /// # Examples
    ///
    /// ```
    /// # #[cfg(feature = "zk")]
    /// # {
    /// # fn example() -> Result<(), stash::Error> {
    /// use stash::zk::ZKCrypto;
    ///
    /// let zk = ZKCrypto::new("my-passphrase-min-16-chars")?;
    /// let encrypted = zk.encrypt(b"secret data")?;
    /// let decrypted = zk.decrypt(&encrypted)?;
    /// assert_eq!(decrypted, b"secret data");
    /// # Ok(())
    /// # }
    /// # }
    /// ```
    pub fn decrypt(&self, encrypted: &str) -> Result<Vec<u8>, Error> {
        // check and remove prefix
        if !is_zk_encrypted(encrypted) {
            return Err(Error::Decryption("missing ZK prefix".to_string()));
        }
        let encoded = &encrypted[ZK_PREFIX.len()..];

        // decode base64
        let decoded = BASE64
            .decode(encoded)
            .map_err(|e| Error::Decryption(format!("base64 decode: {}", e)))?;

        // check minimum size
        if decoded.len() < ZK_MIN_DATA_SIZE {
            return Err(Error::Decryption("data too short".to_string()));
        }

        // extract salt, nonce, ciphertext
        let salt = &decoded[..ZK_SALT_SIZE];
        let nonce_bytes = &decoded[ZK_SALT_SIZE..ZK_SALT_SIZE + ZK_NONCE_SIZE];
        let ciphertext = &decoded[ZK_SALT_SIZE + ZK_NONCE_SIZE..];

        // derive key using argon2id
        let key = self.derive_key(salt);

        // create cipher
        let cipher = Aes256Gcm::new_from_slice(&key)
            .map_err(|e| Error::Decryption(format!("create cipher: {}", e)))?;

        let nonce = Nonce::from_slice(nonce_bytes);

        // decrypt
        let plaintext = cipher
            .decrypt(nonce, ciphertext)
            .map_err(|_| Error::Decryption("decryption failed".to_string()))?;

        Ok(plaintext)
    }

    /// Derive a 32-byte AES key from passphrase and salt using Argon2id
    fn derive_key(&self, salt: &[u8]) -> [u8; ZK_KEY_SIZE] {
        let mut key = [0u8; ZK_KEY_SIZE];
        let argon2 = Argon2::new(
            argon2::Algorithm::Argon2id,
            argon2::Version::V0x13,
            argon2::Params::new(ARGON_MEMORY, ARGON_TIME, ARGON_THREADS, Some(ZK_KEY_SIZE))
                .expect("valid argon2 params"),
        );
        argon2
            .hash_password_into(self.passphrase.as_bytes(), salt, &mut key)
            .expect("argon2 key derivation");
        key
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_is_zk_encrypted() {
        assert!(is_zk_encrypted("$ZK$abc"));
        assert!(!is_zk_encrypted("$ZKabc"));
        assert!(!is_zk_encrypted("abc"));
        assert!(!is_zk_encrypted(""));
    }

    #[test]
    fn test_new_validates_key_length() {
        assert!(ZKCrypto::new("short").is_err());
        assert!(ZKCrypto::new("exactly16chars!!").is_ok());
        assert!(ZKCrypto::new("this-is-a-long-passphrase").is_ok());
    }

    #[test]
    fn test_encrypt_decrypt_roundtrip() {
        let zk = ZKCrypto::new("test-passphrase-16").unwrap();
        let plaintext = b"hello world";

        let encrypted = zk.encrypt(plaintext).unwrap();
        assert!(encrypted.starts_with(ZK_PREFIX));

        let decrypted = zk.decrypt(&encrypted).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_encrypt_produces_different_ciphertexts() {
        let zk = ZKCrypto::new("test-passphrase-16").unwrap();
        let plaintext = b"hello world";

        let encrypted1 = zk.encrypt(plaintext).unwrap();
        let encrypted2 = zk.encrypt(plaintext).unwrap();

        // different salt and nonce should produce different ciphertexts
        assert_ne!(encrypted1, encrypted2);

        // but both should decrypt to the same plaintext
        assert_eq!(zk.decrypt(&encrypted1).unwrap(), plaintext);
        assert_eq!(zk.decrypt(&encrypted2).unwrap(), plaintext);
    }

    #[test]
    fn test_decrypt_with_wrong_passphrase() {
        let zk1 = ZKCrypto::new("passphrase-one-16").unwrap();
        let zk2 = ZKCrypto::new("passphrase-two-16").unwrap();

        let encrypted = zk1.encrypt(b"secret").unwrap();
        let result = zk2.decrypt(&encrypted);

        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), Error::Decryption(_)));
    }

    #[test]
    fn test_decrypt_invalid_format() {
        let zk = ZKCrypto::new("test-passphrase-16").unwrap();

        // missing prefix
        assert!(zk.decrypt("not-zk-encrypted").is_err());

        // invalid base64
        assert!(zk.decrypt("$ZK$!!!invalid!!!").is_err());

        // too short
        assert!(zk.decrypt("$ZK$YWJj").is_err());
    }

    #[test]
    fn test_empty_plaintext() {
        let zk = ZKCrypto::new("test-passphrase-16").unwrap();
        let plaintext = b"";

        let encrypted = zk.encrypt(plaintext).unwrap();
        let decrypted = zk.decrypt(&encrypted).unwrap();

        assert_eq!(decrypted, plaintext);
    }
}
