package com.github.umputun.stash;

import com.github.umputun.stash.errors.DecryptionError;
import com.github.umputun.stash.errors.StashException;
import org.bouncycastle.crypto.generators.Argon2BytesGenerator;
import org.bouncycastle.crypto.params.Argon2Parameters;

import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.Base64;

/**
 * Zero-knowledge encryption using AES-256-GCM with Argon2id key derivation.
 * <p>
 * The encryption format is: $ZK$&lt;base64(salt || nonce || ciphertext || tag)&gt;
 * <p>
 * This implementation is compatible with Go, Python, and TypeScript Stash SDKs.
 */
public final class ZKCrypto {

    /** prefix for zero-knowledge encrypted values */
    static final String ZK_PREFIX = "$ZK$";

    /** salt size in bytes */
    static final int SALT_SIZE = 16;

    /** nonce size in bytes (AES-GCM standard) */
    static final int NONCE_SIZE = 12;

    /** AES key size in bytes (256 bits) */
    static final int KEY_SIZE = 32;

    /** GCM tag size in bits */
    static final int GCM_TAG_BITS = 128;

    /** minimum passphrase length in bytes (UTF-8) */
    static final int MIN_PASSPHRASE_BYTES = 16;

    // argon2id parameters (must match other SDKs)
    private static final int ARGON2_ITERATIONS = 1;
    private static final int ARGON2_MEMORY_KB = 64 * 1024; // 64 MB
    private static final int ARGON2_PARALLELISM = 4;

    private final byte[] passphrase;
    private final SecureRandom random;

    /**
     * Creates a new ZKCrypto instance with the given passphrase.
     *
     * @param passphrase the encryption passphrase (minimum 16 bytes UTF-8)
     * @throws StashException if passphrase is too short
     */
    public ZKCrypto(String passphrase) {
        if (passphrase == null) {
            throw new StashException("passphrase cannot be null");
        }
        byte[] passphraseBytes = passphrase.getBytes(StandardCharsets.UTF_8);
        if (passphraseBytes.length < MIN_PASSPHRASE_BYTES) {
            throw new StashException("passphrase must be at least " + MIN_PASSPHRASE_BYTES + " bytes");
        }
        this.passphrase = passphraseBytes;
        this.random = new SecureRandom();
    }

    /**
     * Encrypts plaintext and returns a ZK-formatted string.
     *
     * @param plaintext the data to encrypt
     * @return encrypted string in format: $ZK$&lt;base64&gt;
     */
    public String encrypt(byte[] plaintext) {
        try {
            // generate random salt and nonce
            byte[] salt = new byte[SALT_SIZE];
            byte[] nonce = new byte[NONCE_SIZE];
            random.nextBytes(salt);
            random.nextBytes(nonce);

            // derive key using Argon2id
            byte[] key = deriveKey(passphrase, salt);

            // encrypt with AES-256-GCM
            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
            SecretKeySpec keySpec = new SecretKeySpec(key, "AES");
            GCMParameterSpec gcmSpec = new GCMParameterSpec(GCM_TAG_BITS, nonce);
            cipher.init(Cipher.ENCRYPT_MODE, keySpec, gcmSpec);
            byte[] ciphertext = cipher.doFinal(plaintext);

            // combine: salt || nonce || ciphertext (includes GCM tag)
            byte[] combined = new byte[SALT_SIZE + NONCE_SIZE + ciphertext.length];
            System.arraycopy(salt, 0, combined, 0, SALT_SIZE);
            System.arraycopy(nonce, 0, combined, SALT_SIZE, NONCE_SIZE);
            System.arraycopy(ciphertext, 0, combined, SALT_SIZE + NONCE_SIZE, ciphertext.length);

            // encode and add prefix
            return ZK_PREFIX + Base64.getEncoder().encodeToString(combined);
        } catch (Exception e) {
            throw new StashException("encryption failed: " + e.getMessage(), e);
        }
    }

    /**
     * Encrypts a string and returns a ZK-formatted string.
     *
     * @param plaintext the string to encrypt
     * @return encrypted string in format: $ZK$&lt;base64&gt;
     */
    public String encrypt(String plaintext) {
        return encrypt(plaintext.getBytes(StandardCharsets.UTF_8));
    }

    /**
     * Decrypts a ZK-formatted string to bytes.
     *
     * @param encrypted the encrypted string (must start with $ZK$)
     * @return decrypted bytes
     * @throws DecryptionError if decryption fails
     */
    public byte[] decryptBytes(String encrypted) {
        if (!isZKEncrypted(encrypted)) {
            throw new DecryptionError("not a ZK-encrypted value");
        }

        try {
            // decode base64 payload
            String payload = encrypted.substring(ZK_PREFIX.length());
            byte[] combined = Base64.getDecoder().decode(payload);

            // minimum: salt + nonce + GCM tag (16 bytes)
            int minLength = SALT_SIZE + NONCE_SIZE + (GCM_TAG_BITS / 8);
            if (combined.length < minLength) {
                throw new DecryptionError("invalid ZK payload: too short");
            }

            // extract salt, nonce, and ciphertext
            byte[] salt = new byte[SALT_SIZE];
            byte[] nonce = new byte[NONCE_SIZE];
            byte[] ciphertext = new byte[combined.length - SALT_SIZE - NONCE_SIZE];

            System.arraycopy(combined, 0, salt, 0, SALT_SIZE);
            System.arraycopy(combined, SALT_SIZE, nonce, 0, NONCE_SIZE);
            System.arraycopy(combined, SALT_SIZE + NONCE_SIZE, ciphertext, 0, ciphertext.length);

            // derive key using Argon2id
            byte[] key = deriveKey(passphrase, salt);

            // decrypt with AES-256-GCM
            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
            SecretKeySpec keySpec = new SecretKeySpec(key, "AES");
            GCMParameterSpec gcmSpec = new GCMParameterSpec(GCM_TAG_BITS, nonce);
            cipher.init(Cipher.DECRYPT_MODE, keySpec, gcmSpec);
            return cipher.doFinal(ciphertext);
        } catch (DecryptionError e) {
            throw e;
        } catch (Exception e) {
            throw new DecryptionError("decryption failed: " + e.getMessage(), e);
        }
    }

    /**
     * Decrypts a ZK-formatted string to a string.
     *
     * @param encrypted the encrypted string (must start with $ZK$)
     * @return decrypted string
     * @throws DecryptionError if decryption fails
     */
    public String decrypt(String encrypted) {
        return new String(decryptBytes(encrypted), StandardCharsets.UTF_8);
    }

    /**
     * Checks if a value is ZK-encrypted.
     *
     * @param value the value to check
     * @return true if the value starts with $ZK$ and has content after
     */
    public static boolean isZKEncrypted(String value) {
        return value != null && value.length() > ZK_PREFIX.length() && value.startsWith(ZK_PREFIX);
    }

    /**
     * Checks if a byte array contains a ZK-encrypted value.
     *
     * @param value the bytes to check
     * @return true if the bytes represent a ZK-encrypted string
     */
    public static boolean isZKEncrypted(byte[] value) {
        if (value == null || value.length <= ZK_PREFIX.length()) {
            return false;
        }
        String prefix = new String(value, 0, ZK_PREFIX.length(), StandardCharsets.UTF_8);
        return ZK_PREFIX.equals(prefix);
    }

    /**
     * Derives an AES key from a passphrase and salt using Argon2id.
     */
    private static byte[] deriveKey(byte[] passphrase, byte[] salt) {
        Argon2Parameters params = new Argon2Parameters.Builder(Argon2Parameters.ARGON2_id)
                .withSalt(salt)
                .withIterations(ARGON2_ITERATIONS)
                .withMemoryAsKB(ARGON2_MEMORY_KB)
                .withParallelism(ARGON2_PARALLELISM)
                .build();

        Argon2BytesGenerator generator = new Argon2BytesGenerator();
        generator.init(params);

        byte[] key = new byte[KEY_SIZE];
        generator.generateBytes(passphrase, key);
        return key;
    }
}
