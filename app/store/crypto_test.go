package store

import (
	"bytes"
	"crypto/rand"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestIsSecret(t *testing.T) {
	tests := []struct {
		key      string
		expected bool
	}{
		// secret paths
		{"secrets", true},
		{"secrets/db/password", true},
		{"secrets/api-key", true},
		{"app/secrets/db", true},
		{"app/secrets/config/key", true},
		{"blah/secrets/config/foo", true},
		{"app/secrets", true},
		{"foo/bar/secrets", true},

		// non-secret paths
		{"config/database", false},
		{"app/settings", false},
		{"my-secrets/foo", false},      // not a path segment
		{"secretsabc/foo", false},      // not a path segment
		{"foosecrets/bar", false},      // not a path segment
		{"app/mysecrets/key", false},   // not a path segment
		{"app/secrets-old/key", false}, // not a path segment
		{"", false},
	}

	for _, tt := range tests {
		t.Run(tt.key, func(t *testing.T) {
			assert.Equal(t, tt.expected, IsSecret(tt.key), "key: %s", tt.key)
		})
	}
}

func TestNewCrypto(t *testing.T) {
	t.Run("valid key", func(t *testing.T) {
		c, err := NewCrypto([]byte("1234567890123456"))
		require.NoError(t, err)
		assert.NotNil(t, c)
	})

	t.Run("key too short", func(t *testing.T) {
		_, err := NewCrypto([]byte("short"))
		assert.Error(t, err)
	})

	t.Run("nil key", func(t *testing.T) {
		_, err := NewCrypto(nil)
		assert.Error(t, err)
	})
}

func TestCrypto_EncryptDecrypt(t *testing.T) {
	c, err := NewCrypto([]byte("test-master-key-1234567890"))
	require.NoError(t, err)

	tests := []struct {
		name  string
		value []byte
	}{
		{"empty value", []byte{}},
		{"small value", []byte("hello world")},
		{"medium value", []byte("this is a medium length value that contains some data")},
		{"binary data", []byte{0x00, 0x01, 0x02, 0xff, 0xfe, 0xfd}},
		{"unicode", []byte("привет мир 你好世界 🔐")},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			encrypted, err := c.Encrypt(tt.value)
			require.NoError(t, err)
			assert.NotEmpty(t, encrypted)
			assert.NotEqual(t, tt.value, encrypted, "encrypted should differ from original")

			decrypted, err := c.Decrypt(encrypted)
			require.NoError(t, err)
			assert.Equal(t, tt.value, decrypted)
		})
	}
}

func TestCrypto_EncryptDecrypt_LargeValue(t *testing.T) {
	c, err := NewCrypto([]byte("test-master-key-1234567890"))
	require.NoError(t, err)

	// 1 MB of random data
	largeValue := make([]byte, 1024*1024)
	_, err = rand.Read(largeValue)
	require.NoError(t, err)

	encrypted, err := c.Encrypt(largeValue)
	require.NoError(t, err)

	decrypted, err := c.Decrypt(encrypted)
	require.NoError(t, err)
	assert.True(t, bytes.Equal(largeValue, decrypted))
}

func TestCrypto_EncryptDecrypt_DifferentEncryptions(t *testing.T) {
	// each encryption should produce different ciphertext (due to random salt and nonce)
	c, err := NewCrypto([]byte("test-master-key-1234567890"))
	require.NoError(t, err)

	value := []byte("same value")

	encrypted1, err := c.Encrypt(value)
	require.NoError(t, err)

	encrypted2, err := c.Encrypt(value)
	require.NoError(t, err)

	assert.NotEqual(t, encrypted1, encrypted2, "encryptions should differ due to random salt/nonce")

	// both should decrypt to same value
	decrypted1, err := c.Decrypt(encrypted1)
	require.NoError(t, err)

	decrypted2, err := c.Decrypt(encrypted2)
	require.NoError(t, err)

	assert.Equal(t, value, decrypted1)
	assert.Equal(t, value, decrypted2)
}

func TestCrypto_Decrypt_WrongKey(t *testing.T) {
	c1, err := NewCrypto([]byte("correct-master-key-1234567890"))
	require.NoError(t, err)

	c2, err := NewCrypto([]byte("wrong-master-key-0987654321"))
	require.NoError(t, err)

	value := []byte("secret data")
	encrypted, err := c1.Encrypt(value)
	require.NoError(t, err)

	_, err = c2.Decrypt(encrypted)
	assert.ErrorIs(t, err, ErrDecryptionFailed)
}

func TestCrypto_Decrypt_CorruptedData(t *testing.T) {
	c, err := NewCrypto([]byte("test-master-key-1234567890"))
	require.NoError(t, err)

	tests := []struct {
		name string
		data []byte
	}{
		{"empty", []byte{}},
		{"too short", []byte("abc")},
		{"invalid base64", []byte("not-valid-base64!!!")},
		{"truncated ciphertext", []byte("YWJjZGVmZ2hpamtsbW5vcHFyc3R1dnd4eXo=")}, // valid base64 but too short
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := c.Decrypt(tt.data)
			assert.Error(t, err)
		})
	}
}

func TestCrypto_Decrypt_TamperedCiphertext(t *testing.T) {
	c, err := NewCrypto([]byte("test-master-key-1234567890"))
	require.NoError(t, err)

	value := []byte("secret data")
	encrypted, err := c.Encrypt(value)
	require.NoError(t, err)

	// tamper with the ciphertext (flip a byte near the end)
	tampered := make([]byte, len(encrypted))
	copy(tampered, encrypted)
	tampered[len(tampered)-5] ^= 0xff

	_, err = c.Decrypt(tampered)
	assert.Error(t, err)
}

func TestNewCrypto_KeyValidation(t *testing.T) {
	tests := []struct {
		name    string
		key     []byte
		wantErr bool
	}{
		{"nil key", nil, true},
		{"empty key", []byte{}, true},
		{"too short key (15 bytes)", []byte("123456789012345"), true},
		{"minimum valid key (16 bytes)", []byte("1234567890123456"), false},
		{"longer key", []byte("this-is-a-much-longer-key-for-testing"), false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c, err := NewCrypto(tt.key)
			if tt.wantErr {
				require.Error(t, err)
				assert.Nil(t, c)
			} else {
				require.NoError(t, err)
				assert.NotNil(t, c)
			}
		})
	}
}

func TestCrypto_DeriveKey_Consistency(t *testing.T) {
	// test that deriveKey produces consistent results by encrypting the same value
	// twice with the same Crypto instance - the decryption should work for both
	c, err := NewCrypto([]byte("test-master-key-for-derive"))
	require.NoError(t, err)

	value := []byte("test value for key derivation")

	// encrypt multiple times
	encrypted1, err := c.Encrypt(value)
	require.NoError(t, err)

	encrypted2, err := c.Encrypt(value)
	require.NoError(t, err)

	// encryptions should differ (random salt/nonce)
	assert.NotEqual(t, encrypted1, encrypted2)

	// but both should decrypt correctly
	decrypted1, err := c.Decrypt(encrypted1)
	require.NoError(t, err)
	assert.Equal(t, value, decrypted1)

	decrypted2, err := c.Decrypt(encrypted2)
	require.NoError(t, err)
	assert.Equal(t, value, decrypted2)
}

func TestCrypto_DifferentKeys_ProduceDifferentResults(t *testing.T) {
	c1, err := NewCrypto([]byte("first-master-key-1234"))
	require.NoError(t, err)

	c2, err := NewCrypto([]byte("second-master-key-567"))
	require.NoError(t, err)

	value := []byte("same value")

	encrypted1, err := c1.Encrypt(value)
	require.NoError(t, err)

	encrypted2, err := c2.Encrypt(value)
	require.NoError(t, err)

	// c1 can decrypt its own encryption
	decrypted, err := c1.Decrypt(encrypted1)
	require.NoError(t, err)
	assert.Equal(t, value, decrypted)

	// c2 can decrypt its own encryption
	decrypted, err = c2.Decrypt(encrypted2)
	require.NoError(t, err)
	assert.Equal(t, value, decrypted)

	// c1 cannot decrypt c2's encryption
	_, err = c1.Decrypt(encrypted2)
	require.ErrorIs(t, err, ErrDecryptionFailed)

	// c2 cannot decrypt c1's encryption
	_, err = c2.Decrypt(encrypted1)
	require.ErrorIs(t, err, ErrDecryptionFailed)
}
