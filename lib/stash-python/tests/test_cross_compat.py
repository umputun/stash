"""Cross-compatibility tests between Python and Go implementations."""

from pathlib import Path

import pytest

from stash.zk import ZKCrypto

FIXTURES_DIR = Path(__file__).parent / "fixtures"
PASSPHRASE = "cross-compat-key-16"


class TestCrossCompatibility:
    """Tests that verify Python can decrypt Go-encrypted data and vice versa."""

    def test_decrypt_go_fixture(self):
        """Decrypt data encrypted by Go implementation."""
        encrypted_path = FIXTURES_DIR / "go_encrypted.bin"
        plaintext_path = FIXTURES_DIR / "go_plaintext.txt"

        if not encrypted_path.exists():
            pytest.skip("Go fixture not found, run: go test -run TestZKCrypto_GeneratePythonFixture ./lib/stash/")

        encrypted = encrypted_path.read_bytes()
        expected_plaintext = plaintext_path.read_text()

        zk = ZKCrypto(PASSPHRASE)
        decrypted = zk.decrypt(encrypted)

        assert decrypted.decode() == expected_plaintext

    def test_generate_fixture_for_go(self):
        """Generate encrypted data for Go to decrypt."""
        plaintext = "hello from Python! 🐍"

        zk = ZKCrypto(PASSPHRASE)
        encrypted = zk.encrypt(plaintext.encode())

        # write fixtures for Go tests
        FIXTURES_DIR.mkdir(parents=True, exist_ok=True)
        (FIXTURES_DIR / "python_encrypted.bin").write_bytes(encrypted)
        (FIXTURES_DIR / "python_plaintext.txt").write_text(plaintext)

        # verify we can decrypt our own data
        decrypted = zk.decrypt(encrypted)
        assert decrypted.decode() == plaintext


class TestArgon2Parameters:
    """Tests that verify Argon2id parameters match Go implementation."""

    def test_key_derivation_parameters(self):
        """Verify the key derivation produces consistent results with known salt."""
        from stash.zk import ARGON_MEMORY, ARGON_PARALLELISM, ARGON_TIME, ZK_KEY_SIZE

        # these must match Go constants
        assert ARGON_TIME == 1
        assert ARGON_MEMORY == 64 * 1024  # 64 MB in KB
        assert ARGON_PARALLELISM == 4
        assert ZK_KEY_SIZE == 32

    def test_crypto_constants(self):
        """Verify crypto constants match Go implementation."""
        from stash.zk import ZK_GCM_TAG_SIZE, ZK_NONCE_SIZE, ZK_PREFIX, ZK_SALT_SIZE

        assert ZK_PREFIX == "$ZK$"
        assert ZK_SALT_SIZE == 16
        assert ZK_NONCE_SIZE == 12
        assert ZK_GCM_TAG_SIZE == 16
