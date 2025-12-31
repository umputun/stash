"""Tests for zero-knowledge encryption."""

import pytest

from stash.errors import DecryptionError
from stash.zk import ZKCrypto, is_zk_encrypted


class TestIsZKEncrypted:
    def test_encrypted_value(self):
        assert is_zk_encrypted(b"$ZK$somedata") is True

    def test_unencrypted_value(self):
        assert is_zk_encrypted(b"plain text") is False

    def test_empty_value(self):
        assert is_zk_encrypted(b"") is False

    def test_prefix_only(self):
        assert is_zk_encrypted(b"$ZK$") is False

    def test_partial_prefix(self):
        assert is_zk_encrypted(b"$ZK") is False


class TestZKCrypto:
    def test_passphrase_too_short(self):
        with pytest.raises(ValueError, match="at least 16 characters"):
            ZKCrypto("short")

    def test_passphrase_minimum_length(self):
        # exactly 16 characters should work
        zk = ZKCrypto("a" * 16)
        assert zk is not None

    def test_encrypt_decrypt_roundtrip(self):
        zk = ZKCrypto("test-passphrase-16chars")
        plaintext = b"hello, world!"

        encrypted = zk.encrypt(plaintext)
        assert is_zk_encrypted(encrypted)
        assert encrypted.startswith(b"$ZK$")

        decrypted = zk.decrypt(encrypted)
        assert decrypted == plaintext

    def test_encrypt_decrypt_empty(self):
        zk = ZKCrypto("test-passphrase-16chars")
        plaintext = b""

        encrypted = zk.encrypt(plaintext)
        decrypted = zk.decrypt(encrypted)
        assert decrypted == plaintext

    def test_encrypt_decrypt_binary(self):
        zk = ZKCrypto("test-passphrase-16chars")
        plaintext = bytes(range(256))

        encrypted = zk.encrypt(plaintext)
        decrypted = zk.decrypt(encrypted)
        assert decrypted == plaintext

    def test_encrypt_decrypt_unicode(self):
        zk = ZKCrypto("test-passphrase-16chars")
        plaintext = "hello 世界 🌍".encode()

        encrypted = zk.encrypt(plaintext)
        decrypted = zk.decrypt(encrypted)
        assert decrypted == plaintext

    def test_different_encryptions_produce_different_output(self):
        zk = ZKCrypto("test-passphrase-16chars")
        plaintext = b"hello"

        encrypted1 = zk.encrypt(plaintext)
        encrypted2 = zk.encrypt(plaintext)

        # different due to random salt and nonce
        assert encrypted1 != encrypted2

        # but both decrypt to same plaintext
        assert zk.decrypt(encrypted1) == plaintext
        assert zk.decrypt(encrypted2) == plaintext

    def test_wrong_passphrase_fails(self):
        zk1 = ZKCrypto("passphrase-one-16chars")
        zk2 = ZKCrypto("passphrase-two-16chars")

        encrypted = zk1.encrypt(b"secret")

        with pytest.raises(DecryptionError):
            zk2.decrypt(encrypted)

    def test_decrypt_invalid_prefix(self):
        zk = ZKCrypto("test-passphrase-16chars")

        with pytest.raises(DecryptionError, match="missing prefix"):
            zk.decrypt(b"not encrypted")

    def test_decrypt_invalid_base64(self):
        zk = ZKCrypto("test-passphrase-16chars")

        with pytest.raises(DecryptionError, match="base64"):
            zk.decrypt(b"$ZK$not-valid-base64!!!")

    def test_decrypt_truncated_data(self):
        zk = ZKCrypto("test-passphrase-16chars")

        # too short to contain salt + nonce + tag
        with pytest.raises(DecryptionError, match="too short"):
            zk.decrypt(b"$ZK$YWJj")  # "abc" in base64

    def test_decrypt_corrupted_data(self):
        zk = ZKCrypto("test-passphrase-16chars")
        encrypted = zk.encrypt(b"hello")

        # corrupt by replacing with a different valid base64 char
        # use 'A' or 'B' - guaranteed different from at least one
        original_byte = encrypted[20]
        replacement = b"A" if original_byte != ord("A") else b"B"
        corrupted = encrypted[:20] + replacement + encrypted[21:]

        with pytest.raises(DecryptionError):
            zk.decrypt(corrupted)

    def test_clear_passphrase(self):
        zk = ZKCrypto("test-passphrase-16chars")
        original_len = len(zk._passphrase)

        zk.clear()

        # passphrase should be zeroed
        assert zk._passphrase == b"\x00" * original_len

    def test_large_plaintext(self):
        zk = ZKCrypto("test-passphrase-16chars")
        plaintext = b"x" * 1_000_000  # 1 MB

        encrypted = zk.encrypt(plaintext)
        decrypted = zk.decrypt(encrypted)
        assert decrypted == plaintext
