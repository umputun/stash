"""Zero-knowledge encryption using AES-256-GCM with Argon2id key derivation.

This implementation is compatible with the Go client library.
"""

import base64
import os
from typing import Final

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from stash.errors import DecryptionError

# crypto constants (must match Go implementation)
ZK_PREFIX: Final[str] = "$ZK$"
ZK_SALT_SIZE: Final[int] = 16
ZK_NONCE_SIZE: Final[int] = 12  # AES-GCM standard nonce size
ZK_KEY_SIZE: Final[int] = 32  # AES-256
ZK_MIN_KEY_LEN: Final[int] = 16
ZK_GCM_TAG_SIZE: Final[int] = 16
ZK_MIN_DATA_SIZE: Final[int] = ZK_SALT_SIZE + ZK_NONCE_SIZE + ZK_GCM_TAG_SIZE

# argon2id parameters (must match Go implementation)
ARGON_TIME: Final[int] = 1
ARGON_MEMORY: Final[int] = 64 * 1024  # 64 MB in KB
ARGON_PARALLELISM: Final[int] = 4


def is_zk_encrypted(value: bytes) -> bool:
    """Check if a value is ZK-encrypted by looking for the $ZK$ prefix."""
    return len(value) > len(ZK_PREFIX) and value[: len(ZK_PREFIX)] == ZK_PREFIX.encode()


class ZKCrypto:
    """Client-side zero-knowledge encryption using AES-256-GCM with Argon2id."""

    def __init__(self, passphrase: str):
        """Create a new ZKCrypto instance.

        Args:
            passphrase: Encryption passphrase (minimum 16 characters)

        Raises:
            ValueError: If passphrase is too short
        """
        if len(passphrase) < ZK_MIN_KEY_LEN:
            raise ValueError("passphrase must be at least 16 characters")
        self._passphrase = passphrase.encode()

    def encrypt(self, plaintext: bytes) -> bytes:
        """Encrypt plaintext using AES-256-GCM with Argon2id key derivation.

        Format: $ZK$<base64(salt || nonce || ciphertext || tag)>

        Args:
            plaintext: Data to encrypt

        Returns:
            Encrypted data with $ZK$ prefix
        """
        # generate random salt
        salt = os.urandom(ZK_SALT_SIZE)

        # derive key using argon2id
        key = self._derive_key(salt)

        # generate random nonce
        nonce = os.urandom(ZK_NONCE_SIZE)

        # encrypt using AES-GCM (includes authentication tag)
        aesgcm = AESGCM(key)
        ciphertext = aesgcm.encrypt(nonce, plaintext, None)

        # combine: salt || nonce || ciphertext (with tag appended by AESGCM)
        combined = salt + nonce + ciphertext

        # encode as base64 with prefix
        encoded = base64.b64encode(combined).decode()
        return (ZK_PREFIX + encoded).encode()

    def decrypt(self, encrypted: bytes) -> bytes:
        """Decrypt a ZK-encrypted value.

        Args:
            encrypted: Encrypted data with $ZK$ prefix

        Returns:
            Decrypted plaintext

        Raises:
            DecryptionError: If decryption fails
        """
        # check and remove prefix
        if not is_zk_encrypted(encrypted):
            raise DecryptionError("invalid ZK encrypted data: missing prefix")

        encoded = encrypted[len(ZK_PREFIX) :]

        # decode base64 (validate=True for strict parity with Go's base64 decoder)
        try:
            decoded = base64.b64decode(encoded, validate=True)
        except Exception as e:
            raise DecryptionError(f"base64 decode failed: {e}") from e

        # check minimum size
        if len(decoded) < ZK_MIN_DATA_SIZE:
            raise DecryptionError("invalid ZK encrypted data: too short")

        # extract salt, nonce, ciphertext
        salt = decoded[:ZK_SALT_SIZE]
        nonce = decoded[ZK_SALT_SIZE : ZK_SALT_SIZE + ZK_NONCE_SIZE]
        ciphertext = decoded[ZK_SALT_SIZE + ZK_NONCE_SIZE :]

        # derive key using argon2id
        key = self._derive_key(salt)

        # decrypt using AES-GCM
        try:
            aesgcm = AESGCM(key)
            plaintext = aesgcm.decrypt(nonce, ciphertext, None)
        except Exception as e:
            raise DecryptionError("decryption failed: wrong key or corrupted data") from e

        return plaintext

    def _derive_key(self, salt: bytes) -> bytes:
        """Derive a 32-byte AES key from passphrase and salt using Argon2id."""
        # use argon2-cffi or cryptography's argon2
        from argon2.low_level import Type, hash_secret_raw

        return hash_secret_raw(
            secret=self._passphrase,
            salt=salt,
            time_cost=ARGON_TIME,
            memory_cost=ARGON_MEMORY,
            parallelism=ARGON_PARALLELISM,
            hash_len=ZK_KEY_SIZE,
            type=Type.ID,
        )

    def clear(self) -> None:
        """Clear the passphrase from memory (best effort).

        Note: This is best-effort; Python's garbage collector may have
        copied the data and the interpreter may optimize away the zeroing.
        """
        # overwrite with zeros
        self._passphrase = b"\x00" * len(self._passphrase)
