package io.github.umputun.stash;

import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Cross-compatibility tests with Go, Python, and TypeScript SDKs.
 * Tests that Java SDK can decrypt values encrypted by other SDKs.
 */
class CrossCompatTest {

    // must match the passphrase used to generate fixtures in other SDKs
    private static final String CROSS_COMPAT_PASSPHRASE = "cross-compat-key-16";

    @Test
    void decryptGoEncryptedValue() throws IOException {
        String encrypted = readFixture("go_encrypted.bin");
        String expectedPlaintext = readFixture("go_plaintext.txt");

        ZKCrypto crypto = new ZKCrypto(CROSS_COMPAT_PASSPHRASE);
        String decrypted = crypto.decrypt(encrypted);

        assertThat(decrypted).isEqualTo(expectedPlaintext);
    }

    @Test
    void decryptPythonEncryptedValue() throws IOException {
        String encrypted = readFixture("python_encrypted.bin");
        String expectedPlaintext = readFixture("python_plaintext.txt");

        ZKCrypto crypto = new ZKCrypto(CROSS_COMPAT_PASSPHRASE);
        String decrypted = crypto.decrypt(encrypted);

        assertThat(decrypted).isEqualTo(expectedPlaintext);
    }

    @Test
    void decryptTypescriptEncryptedValue() throws IOException {
        String encrypted = readFixture("typescript_encrypted.bin");
        String expectedPlaintext = readFixture("typescript_plaintext.txt");

        ZKCrypto crypto = new ZKCrypto(CROSS_COMPAT_PASSPHRASE);
        String decrypted = crypto.decrypt(encrypted);

        assertThat(decrypted).isEqualTo(expectedPlaintext);
    }

    @Test
    void allSdksProduceSameDecryptedContent() throws IOException {
        ZKCrypto crypto = new ZKCrypto(CROSS_COMPAT_PASSPHRASE);

        String goDecrypted = crypto.decrypt(readFixture("go_encrypted.bin"));
        String pythonDecrypted = crypto.decrypt(readFixture("python_encrypted.bin"));
        String typescriptDecrypted = crypto.decrypt(readFixture("typescript_encrypted.bin"));

        // all should decrypt to language-specific greetings
        assertThat(goDecrypted).contains("Go");
        assertThat(pythonDecrypted).contains("Python");
        assertThat(typescriptDecrypted).contains("TypeScript");
    }

    private String readFixture(String name) throws IOException {
        try (InputStream is = getClass().getResourceAsStream("/fixtures/" + name)) {
            if (is == null) {
                throw new IOException("fixture not found: " + name);
            }
            return new String(is.readAllBytes(), StandardCharsets.UTF_8).trim();
        }
    }
}
