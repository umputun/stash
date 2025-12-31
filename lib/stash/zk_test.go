package stash

import (
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/umputun/stash/app/store"
)

func TestIsZKEncrypted(t *testing.T) {
	tests := []struct {
		name     string
		value    []byte
		expected bool
	}{
		{"empty value", []byte{}, false},
		{"nil value", nil, false},
		{"plain text", []byte("hello world"), false},
		{"zk prefix only", []byte("$ZK$"), false},
		{"zk prefix with data", []byte("$ZK$somebase64data"), true},
		{"zk prefix lowercase", []byte("$zk$somedata"), false},
		{"partial prefix", []byte("$ZK"), false},
		{"prefix in middle", []byte("data$ZK$moredata"), false},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			result := isZKEncrypted(tc.value)
			assert.Equal(t, tc.expected, result)
		})
	}
}

func TestZKCrypto_Encrypt(t *testing.T) {
	zk, err := newZKCrypto("test-passphrase-min-16")
	require.NoError(t, err)

	tests := []struct {
		name      string
		plaintext []byte
	}{
		{"simple text", []byte("hello world")},
		{"empty value", []byte{}},
		{"binary data", []byte{0x00, 0x01, 0x02, 0xff}},
		{"long text", []byte("this is a much longer text that spans multiple words and sentences")},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			encrypted, err := zk.encrypt(tc.plaintext)
			require.NoError(t, err)
			assert.True(t, isZKEncrypted(encrypted), "encrypted value should have $ZK$ prefix")
			assert.Greater(t, len(encrypted), len(tc.plaintext), "encrypted should be larger than plaintext")
		})
	}
}

func TestZKCrypto_Decrypt(t *testing.T) {
	zk, err := newZKCrypto("test-passphrase-min-16")
	require.NoError(t, err)

	// first encrypt a value
	plaintext := []byte("secret message")
	encrypted, err := zk.encrypt(plaintext)
	require.NoError(t, err)

	// then decrypt it
	decrypted, err := zk.decrypt(encrypted)
	require.NoError(t, err)
	assert.Equal(t, plaintext, decrypted)
}

func TestZKCrypto_RoundTrip(t *testing.T) {
	zk, err := newZKCrypto("test-passphrase-min-16")
	require.NoError(t, err)

	tests := []struct {
		name      string
		plaintext []byte
	}{
		{"simple text", []byte("hello world")},
		{"empty value", []byte{}},
		{"unicode", []byte("привет мир 🌍")},
		{"json", []byte(`{"key": "value", "number": 42}`)},
		{"binary", []byte{0x00, 0x01, 0x02, 0xfe, 0xff}},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			encrypted, err := zk.encrypt(tc.plaintext)
			require.NoError(t, err)

			decrypted, err := zk.decrypt(encrypted)
			require.NoError(t, err)
			assert.Equal(t, tc.plaintext, decrypted)
		})
	}
}

func TestZKCrypto_WrongKey(t *testing.T) {
	zk1, err := newZKCrypto("first-passphrase-16")
	require.NoError(t, err)

	zk2, err := newZKCrypto("second-passphrase-16")
	require.NoError(t, err)

	// encrypt with first key
	plaintext := []byte("secret data")
	encrypted, err := zk1.encrypt(plaintext)
	require.NoError(t, err)

	// try to decrypt with second key
	_, err = zk2.decrypt(encrypted)
	assert.ErrorIs(t, err, ErrZKDecryptionFailed)
}

func TestZKCrypto_InvalidData(t *testing.T) {
	zk, err := newZKCrypto("test-passphrase-min-16")
	require.NoError(t, err)

	tests := []struct {
		name  string
		value []byte
	}{
		{"missing prefix", []byte("notencrypted")},
		{"prefix only", []byte("$ZK$")},
		{"invalid base64", []byte("$ZK$not-valid-base64!!!")},
		{"truncated data", []byte("$ZK$YWJj")}, // valid base64 but too short
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, err := zk.decrypt(tc.value)
			assert.Error(t, err)
		})
	}
}

func TestZKCrypto_UniqueEncryptions(t *testing.T) {
	zk, err := newZKCrypto("test-passphrase-min-16")
	require.NoError(t, err)

	plaintext := []byte("same message")

	// encrypt same message twice
	enc1, err := zk.encrypt(plaintext)
	require.NoError(t, err)

	enc2, err := zk.encrypt(plaintext)
	require.NoError(t, err)

	// should produce different ciphertexts (due to random salt/nonce)
	assert.NotEqual(t, enc1, enc2, "same plaintext should produce different ciphertexts")

	// but both should decrypt to the same value
	dec1, err := zk.decrypt(enc1)
	require.NoError(t, err)

	dec2, err := zk.decrypt(enc2)
	require.NoError(t, err)

	assert.Equal(t, dec1, dec2)
	assert.Equal(t, plaintext, dec1)
}

func TestNewZKCrypto_Validation(t *testing.T) {
	tests := []struct {
		name       string
		passphrase string
		wantError  bool
	}{
		{"valid 16 chars", "1234567890123456", false},
		{"valid 32 chars", "12345678901234567890123456789012", false},
		{"too short", "short", true},
		{"empty", "", true},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, err := newZKCrypto(tc.passphrase)
			if tc.wantError {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestZKCrypto_CrossCompatibility(t *testing.T) {
	// verify lib/stash.zkCrypto can decrypt what app/store.ZKCrypto encrypts (and vice versa)
	// this ensures both implementations use identical crypto parameters

	passphrase := "test-passphrase-min-16"
	plaintext := "secret value to encrypt"

	t.Run("lib can decrypt store encrypted value", func(t *testing.T) {
		// encrypt with store.ZKCrypto
		storeZK, err := store.NewZKCrypto([]byte(passphrase))
		require.NoError(t, err)
		encrypted, err := storeZK.Encrypt([]byte(plaintext))
		require.NoError(t, err)

		// decrypt with lib.zkCrypto
		libZK, err := newZKCrypto(passphrase)
		require.NoError(t, err)
		decrypted, err := libZK.decrypt(encrypted)
		require.NoError(t, err)

		assert.Equal(t, plaintext, string(decrypted))
	})

	t.Run("store can decrypt lib encrypted value", func(t *testing.T) {
		// encrypt with lib.zkCrypto
		libZK, err := newZKCrypto(passphrase)
		require.NoError(t, err)
		encrypted, err := libZK.encrypt([]byte(plaintext))
		require.NoError(t, err)

		// decrypt with store.ZKCrypto
		storeZK, err := store.NewZKCrypto([]byte(passphrase))
		require.NoError(t, err)
		decrypted, err := storeZK.Decrypt(encrypted)
		require.NoError(t, err)

		assert.Equal(t, plaintext, string(decrypted))
	})
}

func TestZKCrypto_GeneratePythonFixture(t *testing.T) {
	// generates encrypted fixture for Python cross-compatibility testing
	// run with: go test -run TestZKCrypto_GeneratePythonFixture -v
	// fixture files are committed to the repo for Python tests to use

	const (
		passphrase  = "cross-compat-key-16"
		plaintext   = "hello from Go! 🎉"
		fixturePath = "../stash-python/tests/fixtures/"
	)

	zk, err := newZKCrypto(passphrase)
	require.NoError(t, err)

	encrypted, err := zk.encrypt([]byte(plaintext))
	require.NoError(t, err)

	// write encrypted data
	err = os.WriteFile(fixturePath+"go_encrypted.bin", encrypted, 0o600)
	require.NoError(t, err)

	// write plaintext for reference
	err = os.WriteFile(fixturePath+"go_plaintext.txt", []byte(plaintext), 0o600)
	require.NoError(t, err)

	t.Logf("generated fixtures in %s", fixturePath)
	t.Logf("encrypted: %s", string(encrypted))
}

func TestZKCrypto_DecryptPythonFixture(t *testing.T) {
	// decrypts fixture generated by Python for cross-compatibility verification
	// run Python's test_cross_compat.py first to generate python_encrypted.bin

	const (
		passphrase  = "cross-compat-key-16"
		fixturePath = "../stash-python/tests/fixtures/"
	)

	encrypted, err := os.ReadFile(fixturePath + "python_encrypted.bin")
	if os.IsNotExist(err) {
		t.Skip("python fixture not found, run Python tests first")
	}
	require.NoError(t, err)

	expectedPlaintext, err := os.ReadFile(fixturePath + "python_plaintext.txt")
	require.NoError(t, err)

	zk, err := newZKCrypto(passphrase)
	require.NoError(t, err)

	decrypted, err := zk.decrypt(encrypted)
	require.NoError(t, err)

	assert.Equal(t, string(expectedPlaintext), string(decrypted))
	t.Logf("successfully decrypted Python fixture: %s", string(decrypted))
}
