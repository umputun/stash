package stash

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"

	"golang.org/x/crypto/argon2"
)

const (
	zkPrefix      = "$ZK$"
	zkSaltSize    = 16
	zkNonceSize   = 12 // AES-GCM standard nonce size
	zkKeySize     = 32 // AES-256
	zkMinKeyLen   = 16
	zkMinDataSize = zkSaltSize + zkNonceSize + 16 // salt + nonce + gcm tag (minimum)

	// argon2id parameters
	argonTime    = 1
	argonMemory  = 64 * 1024 // 64 MB
	argonThreads = 4
)

// ErrZKDecryptionFailed is returned when ZK decryption fails (wrong key or corrupted data).
var ErrZKDecryptionFailed = errors.New("zk decryption failed")

// IsZKEncrypted checks if a value is ZK-encrypted by looking for the $ZK$ prefix.
func IsZKEncrypted(value []byte) bool {
	return len(value) > len(zkPrefix) && string(value[:len(zkPrefix)]) == zkPrefix
}

// IsValidZKPayload checks if a ZK value has valid format.
// Returns true if value has $ZK$ prefix followed by valid base64 of sufficient length.
// This validates format only, not cryptographic correctness (zero-knowledge preserved).
func IsValidZKPayload(value []byte) bool {
	if !IsZKEncrypted(value) {
		return false
	}
	encoded := value[len(zkPrefix):]

	// decode base64
	decoded, err := base64.StdEncoding.DecodeString(string(encoded))
	if err != nil {
		return false
	}

	// check minimum size: salt(16) + nonce(12) + tag(16) = 44 bytes
	return len(decoded) >= zkMinDataSize
}

// ZKCrypto handles client-side zero-knowledge encryption using AES-256-GCM with Argon2id key derivation.
type ZKCrypto struct {
	passphrase []byte
}

// NewZKCrypto creates a new ZKCrypto instance with the given passphrase.
// Passphrase must be at least 16 bytes.
func NewZKCrypto(passphrase []byte) (*ZKCrypto, error) {
	if len(passphrase) < zkMinKeyLen {
		return nil, errors.New("passphrase must be at least 16 bytes")
	}
	return &ZKCrypto{passphrase: passphrase}, nil
}

// Encrypt encrypts plaintext using AES-256-GCM with Argon2id key derivation.
// Format: $ZK$<base64(salt || nonce || ciphertext || tag)>
func (z *ZKCrypto) Encrypt(plaintext []byte) ([]byte, error) {
	// generate random salt
	salt := make([]byte, zkSaltSize)
	if _, err := rand.Read(salt); err != nil {
		return nil, fmt.Errorf("generate salt: %w", err)
	}

	// derive key using argon2id
	key := z.deriveKey(salt)

	// create AES-GCM cipher
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("create cipher: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("create gcm: %w", err)
	}

	// generate random nonce
	nonce := make([]byte, zkNonceSize)
	if _, err := rand.Read(nonce); err != nil {
		return nil, fmt.Errorf("generate nonce: %w", err)
	}

	// encrypt using GCM (includes authentication tag)
	ciphertext := gcm.Seal(nil, nonce, plaintext, nil)

	// combine: salt || nonce || ciphertext (with tag appended)
	combined := make([]byte, 0, zkSaltSize+zkNonceSize+len(ciphertext))
	combined = append(combined, salt...)
	combined = append(combined, nonce...)
	combined = append(combined, ciphertext...)

	// encode as base64 with prefix
	encoded := base64.StdEncoding.EncodeToString(combined)
	return []byte(zkPrefix + encoded), nil
}

// Decrypt decrypts a ZK-encrypted value.
func (z *ZKCrypto) Decrypt(encrypted []byte) ([]byte, error) {
	// check and remove prefix
	if !IsZKEncrypted(encrypted) {
		return nil, ErrZKDecryptionFailed
	}
	encoded := encrypted[len(zkPrefix):]

	// decode base64
	decoded, err := base64.StdEncoding.DecodeString(string(encoded))
	if err != nil {
		return nil, fmt.Errorf("base64 decode: %w", err)
	}

	// check minimum size
	if len(decoded) < zkMinDataSize {
		return nil, ErrZKDecryptionFailed
	}

	// extract salt, nonce, ciphertext
	salt := decoded[:zkSaltSize]
	nonce := decoded[zkSaltSize : zkSaltSize+zkNonceSize]
	ciphertext := decoded[zkSaltSize+zkNonceSize:]

	// derive key using argon2id
	key := z.deriveKey(salt)

	// create AES-GCM cipher
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("create cipher: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("create gcm: %w", err)
	}

	// decrypt
	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, ErrZKDecryptionFailed
	}

	// normalize nil to empty slice for consistency
	if plaintext == nil {
		return []byte{}, nil
	}
	return plaintext, nil
}

// deriveKey derives a 32-byte AES key from passphrase and salt using Argon2id.
func (z *ZKCrypto) deriveKey(salt []byte) []byte {
	return argon2.IDKey(z.passphrase, salt, argonTime, argonMemory, argonThreads, zkKeySize)
}

// Clear securely clears the passphrase from memory.
// note: this is best-effort; Go's GC may have copied the data and the compiler
// may optimize away the zeroing if it determines the memory won't be read again.
func (z *ZKCrypto) Clear() {
	for i := range z.passphrase {
		z.passphrase[i] = 0
	}
}
