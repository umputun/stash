package io.github.umputun.stash;

import io.github.umputun.stash.errors.DecryptionError;
import io.github.umputun.stash.errors.StashException;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class ZKCryptoTest {

    private static final String VALID_PASSPHRASE = "test-passphrase-16"; // 18 bytes

    @Test
    void encryptDecryptRoundTrip() {
        ZKCrypto crypto = new ZKCrypto(VALID_PASSPHRASE);
        String plaintext = "hello, world!";

        String encrypted = crypto.encrypt(plaintext);

        assertThat(encrypted).startsWith("$ZK$");
        assertThat(crypto.decrypt(encrypted)).isEqualTo(plaintext);
    }

    @Test
    void encryptDecryptBytesRoundTrip() {
        ZKCrypto crypto = new ZKCrypto(VALID_PASSPHRASE);
        byte[] plaintext = new byte[]{0x00, 0x01, 0x02, (byte) 0xff, (byte) 0xfe};

        String encrypted = crypto.encrypt(plaintext);

        assertThat(encrypted).startsWith("$ZK$");
        assertThat(crypto.decryptBytes(encrypted)).isEqualTo(plaintext);
    }

    @Test
    void encryptProducesDifferentOutputEachTime() {
        ZKCrypto crypto = new ZKCrypto(VALID_PASSPHRASE);
        String plaintext = "test data";

        String encrypted1 = crypto.encrypt(plaintext);
        String encrypted2 = crypto.encrypt(plaintext);

        // same plaintext should produce different ciphertext due to random salt/nonce
        assertThat(encrypted1).isNotEqualTo(encrypted2);

        // but both should decrypt to the same plaintext
        assertThat(crypto.decrypt(encrypted1)).isEqualTo(plaintext);
        assertThat(crypto.decrypt(encrypted2)).isEqualTo(plaintext);
    }

    @Test
    void decryptWithWrongPassphraseFails() {
        ZKCrypto crypto1 = new ZKCrypto(VALID_PASSPHRASE);
        ZKCrypto crypto2 = new ZKCrypto("different-passphrase");

        String encrypted = crypto1.encrypt("secret data");

        assertThatThrownBy(() -> crypto2.decrypt(encrypted))
                .isInstanceOf(DecryptionError.class);
    }

    @Test
    void passphraseMinimumLengthEnforced() {
        // 15 bytes - too short
        assertThatThrownBy(() -> new ZKCrypto("15-byte-string"))
                .isInstanceOf(StashException.class)
                .hasMessageContaining("16 bytes");

        // exactly 16 bytes - ok
        ZKCrypto crypto = new ZKCrypto("exactly-16-bytes");
        assertThat(crypto.encrypt("test")).startsWith("$ZK$");
    }

    @Test
    void passphraseNullRejected() {
        assertThatThrownBy(() -> new ZKCrypto(null))
                .isInstanceOf(StashException.class)
                .hasMessageContaining("null");
    }

    @Test
    void isZKEncryptedDetectsCorrectly() {
        assertThat(ZKCrypto.isZKEncrypted("$ZK$abc123")).isTrue();
        assertThat(ZKCrypto.isZKEncrypted("$ZK$x")).isTrue();

        // prefix only - not valid
        assertThat(ZKCrypto.isZKEncrypted("$ZK$")).isFalse();
        assertThat(ZKCrypto.isZKEncrypted("$ZK")).isFalse();
        assertThat(ZKCrypto.isZKEncrypted("plaintext")).isFalse();
        assertThat(ZKCrypto.isZKEncrypted("")).isFalse();
        assertThat(ZKCrypto.isZKEncrypted((String) null)).isFalse();
    }

    @Test
    void isZKEncryptedBytesDetectsCorrectly() {
        assertThat(ZKCrypto.isZKEncrypted("$ZK$abc".getBytes(StandardCharsets.UTF_8))).isTrue();

        // prefix only - not valid
        assertThat(ZKCrypto.isZKEncrypted("$ZK$".getBytes(StandardCharsets.UTF_8))).isFalse();
        assertThat(ZKCrypto.isZKEncrypted("plain".getBytes(StandardCharsets.UTF_8))).isFalse();
        assertThat(ZKCrypto.isZKEncrypted(new byte[0])).isFalse();
        assertThat(ZKCrypto.isZKEncrypted((byte[]) null)).isFalse();
    }

    @Test
    void decryptInvalidPayloadFails() {
        ZKCrypto crypto = new ZKCrypto(VALID_PASSPHRASE);

        // not ZK-encrypted
        assertThatThrownBy(() -> crypto.decrypt("plaintext"))
                .isInstanceOf(DecryptionError.class)
                .hasMessageContaining("not a ZK-encrypted");

        // too short payload
        assertThatThrownBy(() -> crypto.decrypt("$ZK$abc"))
                .isInstanceOf(DecryptionError.class);
    }

    @Test
    void handlesEmptyPlaintext() {
        ZKCrypto crypto = new ZKCrypto(VALID_PASSPHRASE);

        String encrypted = crypto.encrypt("");

        assertThat(encrypted).startsWith("$ZK$");
        assertThat(crypto.decrypt(encrypted)).isEmpty();
    }

    @Test
    void handlesLargePlaintext() {
        ZKCrypto crypto = new ZKCrypto(VALID_PASSPHRASE);
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < 10000; i++) {
            sb.append("large payload data ");
        }
        String largePlaintext = sb.toString();

        String encrypted = crypto.encrypt(largePlaintext);
        String decrypted = crypto.decrypt(encrypted);

        assertThat(decrypted).isEqualTo(largePlaintext);
    }

    @Test
    void handlesUnicodePlaintext() {
        ZKCrypto crypto = new ZKCrypto(VALID_PASSPHRASE);
        String unicode = "こんにちは世界 🌍 مرحبا العالم Привет мир";

        String encrypted = crypto.encrypt(unicode);
        String decrypted = crypto.decrypt(encrypted);

        assertThat(decrypted).isEqualTo(unicode);
    }

    @Test
    void handlesUnicodePassphrase() {
        // unicode passphrase with sufficient byte length
        ZKCrypto crypto = new ZKCrypto("パスワード-16bytes"); // more than 16 bytes in UTF-8

        String encrypted = crypto.encrypt("test");
        assertThat(crypto.decrypt(encrypted)).isEqualTo("test");
    }
}
