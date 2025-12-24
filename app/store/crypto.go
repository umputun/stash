package store

import (
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"

	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/nacl/secretbox"
)

const (
	saltSize  = 16
	nonceSize = 24
	keySize   = 32

	// argon2id parameters (same as spot reference implementation)
	argonTime    = 1
	argonMemory  = 64 * 1024 // 64 MB
	argonThreads = 4
)

// ErrDecryptionFailed is returned when decryption fails (wrong key or corrupted data).
var ErrDecryptionFailed = errors.New("decryption failed")

// ErrSecretsNotConfigured is returned when trying to access secrets without a key configured.
var ErrSecretsNotConfigured = errors.New("secrets key not configured")

// IsSecret checks if a key should be treated as a secret based on its path.
// A key is a secret if it contains "secrets" as a path segment:
//   - secrets/db/password → true (starts with secrets/)
//   - app/secrets/db → true (contains /secrets/)
//   - app/secrets → true (ends with /secrets)
//   - secrets → true (exactly "secrets")
//   - my-secrets/foo → false (not a path segment)
//   - secretsabc/foo → false (not a path segment)
func IsSecret(key string) bool {
	return key == "secrets" ||
		strings.HasPrefix(key, "secrets/") ||
		strings.Contains(key, "/secrets/") ||
		strings.HasSuffix(key, "/secrets")
}

// Crypto handles encryption and decryption of secret values using NaCl secretbox with Argon2id key derivation.
type Crypto struct {
	masterKey []byte
}

// NewCrypto creates a new Crypto instance with the given master key.
// Key must be at least 16 bytes.
func NewCrypto(masterKey []byte) (*Crypto, error) {
	if len(masterKey) < 16 {
		return nil, errors.New("master key must be at least 16 bytes")
	}
	return &Crypto{masterKey: masterKey}, nil
}

// Encrypt encrypts the value using NaCl secretbox with Argon2id key derivation.
// Format: base64(salt || nonce || ciphertext)
func (c *Crypto) Encrypt(value []byte) ([]byte, error) {
	// generate random salt
	salt := make([]byte, saltSize)
	if _, err := rand.Read(salt); err != nil {
		return nil, fmt.Errorf("generate salt: %w", err)
	}

	// derive key using argon2id
	derivedKey := c.deriveKey(salt)

	// generate random nonce
	var nonce [nonceSize]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return nil, fmt.Errorf("generate nonce: %w", err)
	}

	// convert derived key to fixed-size array for secretbox
	var key [keySize]byte
	copy(key[:], derivedKey)

	// encrypt using secretbox
	ciphertext := secretbox.Seal(nil, value, &nonce, &key)

	// combine: salt || nonce || ciphertext
	result := make([]byte, 0, saltSize+nonceSize+len(ciphertext))
	result = append(result, salt...)
	result = append(result, nonce[:]...)
	result = append(result, ciphertext...)

	// encode as base64
	encoded := make([]byte, base64.StdEncoding.EncodedLen(len(result)))
	base64.StdEncoding.Encode(encoded, result)

	return encoded, nil
}

// Decrypt decrypts the value that was encrypted with Encrypt.
func (c *Crypto) Decrypt(encrypted []byte) ([]byte, error) {
	// decode base64
	decoded := make([]byte, base64.StdEncoding.DecodedLen(len(encrypted)))
	n, err := base64.StdEncoding.Decode(decoded, encrypted)
	if err != nil {
		return nil, fmt.Errorf("base64 decode: %w", err)
	}
	decoded = decoded[:n]

	// minimum size: salt + nonce + secretbox overhead (16 bytes for poly1305)
	minSize := saltSize + nonceSize + secretbox.Overhead
	if len(decoded) < minSize {
		return nil, ErrDecryptionFailed
	}

	// extract salt, nonce, ciphertext
	salt := decoded[:saltSize]
	var nonce [nonceSize]byte
	copy(nonce[:], decoded[saltSize:saltSize+nonceSize])
	ciphertext := decoded[saltSize+nonceSize:]

	// derive key using argon2id
	derivedKey := c.deriveKey(salt)
	var key [keySize]byte
	copy(key[:], derivedKey)

	// decrypt using secretbox
	plaintext, ok := secretbox.Open(nil, ciphertext, &nonce, &key)
	if !ok {
		return nil, ErrDecryptionFailed
	}
	// normalize nil to empty slice for consistency
	if plaintext == nil {
		return []byte{}, nil
	}
	return plaintext, nil
}

// deriveKey derives a 32-byte key from masterKey and salt using Argon2id.
func (c *Crypto) deriveKey(salt []byte) []byte {
	return argon2.IDKey(c.masterKey, salt, argonTime, argonMemory, argonThreads, keySize)
}
