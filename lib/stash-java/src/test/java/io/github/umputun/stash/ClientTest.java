package io.github.umputun.stash;

import io.github.umputun.stash.errors.*;
import okhttp3.mockwebserver.MockResponse;
import okhttp3.mockwebserver.MockWebServer;
import okhttp3.mockwebserver.RecordedRequest;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.time.Duration;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class ClientTest {

    private MockWebServer server;
    private String baseUrl;

    @BeforeEach
    void setUp() throws IOException {
        server = new MockWebServer();
        server.start();
        baseUrl = server.url("/").toString();
    }

    @AfterEach
    void tearDown() throws IOException {
        server.shutdown();
    }

    @Test
    void getReturnsValue() throws InterruptedException {
        server.enqueue(new MockResponse().setBody("hello world"));

        try (Client client = Client.builder(baseUrl).build()) {
            String value = client.get("app/config");

            assertThat(value).isEqualTo("hello world");
            RecordedRequest request = server.takeRequest();
            assertThat(request.getMethod()).isEqualTo("GET");
            assertThat(request.getPath()).isEqualTo("/kv/app/config");
        }
    }

    @Test
    void getBytesReturnsRawBytes() {
        byte[] data = new byte[]{0x00, 0x01, (byte) 0xff};
        server.enqueue(new MockResponse().setBody(new okio.Buffer().write(data)));

        try (Client client = Client.builder(baseUrl).build()) {
            byte[] result = client.getBytes("binary");
            assertThat(result).isEqualTo(data);
        }
    }

    @Test
    void getThrowsNotFoundFor404() {
        server.enqueue(new MockResponse().setResponseCode(404).setBody("not found"));

        try (Client client = Client.builder(baseUrl).build()) {
            assertThatThrownBy(() -> client.get("missing"))
                    .isInstanceOf(NotFoundError.class)
                    .hasMessageContaining("missing");
        }
    }

    @Test
    void getOrDefaultReturnsDefaultFor404() {
        server.enqueue(new MockResponse().setResponseCode(404));

        try (Client client = Client.builder(baseUrl).build()) {
            String value = client.getOrDefault("missing", "fallback");
            assertThat(value).isEqualTo("fallback");
        }
    }

    @Test
    void setStoresValue() throws InterruptedException {
        server.enqueue(new MockResponse().setResponseCode(200));

        try (Client client = Client.builder(baseUrl).build()) {
            client.set("app/config", "value");

            RecordedRequest request = server.takeRequest();
            assertThat(request.getMethod()).isEqualTo("PUT");
            assertThat(request.getPath()).isEqualTo("/kv/app/config");
            assertThat(request.getBody().readUtf8()).isEqualTo("value");
        }
    }

    @Test
    void setWithFormatSendsHeader() throws InterruptedException {
        server.enqueue(new MockResponse().setResponseCode(200));

        try (Client client = Client.builder(baseUrl).build()) {
            client.set("app/config", "{}", Format.JSON);

            RecordedRequest request = server.takeRequest();
            assertThat(request.getHeader("X-Stash-Format")).isEqualTo("json");
        }
    }

    @Test
    void deleteRemovesKey() throws InterruptedException {
        server.enqueue(new MockResponse().setResponseCode(204));

        try (Client client = Client.builder(baseUrl).build()) {
            client.delete("app/config");

            RecordedRequest request = server.takeRequest();
            assertThat(request.getMethod()).isEqualTo("DELETE");
            assertThat(request.getPath()).isEqualTo("/kv/app/config");
        }
    }

    @Test
    void deleteThrowsNotFoundFor404() {
        server.enqueue(new MockResponse().setResponseCode(404));

        try (Client client = Client.builder(baseUrl).build()) {
            assertThatThrownBy(() -> client.delete("missing"))
                    .isInstanceOf(NotFoundError.class);
        }
    }

    @Test
    void listReturnsKeys() {
        String json = "[{\"key\":\"app/config\",\"size\":100,\"format\":\"json\"," +
                "\"secret\":false,\"zk_encrypted\":false," +
                "\"created_at\":\"2024-01-15T10:30:00Z\",\"updated_at\":\"2024-01-15T10:30:00Z\"}]";
        server.enqueue(new MockResponse().setBody(json));

        try (Client client = Client.builder(baseUrl).build()) {
            List<KeyInfo> keys = client.list();

            assertThat(keys).hasSize(1);
            assertThat(keys.get(0).getKey()).isEqualTo("app/config");
            assertThat(keys.get(0).getSize()).isEqualTo(100);
            assertThat(keys.get(0).getFormat()).isEqualTo(Format.JSON);
        }
    }

    @Test
    void listWithPrefixFilters() throws InterruptedException {
        server.enqueue(new MockResponse().setBody("[]"));

        try (Client client = Client.builder(baseUrl).build()) {
            client.list("app/");

            RecordedRequest request = server.takeRequest();
            assertThat(request.getPath()).isEqualTo("/kv/?prefix=app%2F");
        }
    }

    @Test
    void infoReturnsKeyMetadata() {
        String json = "[{\"key\":\"app/config\",\"size\":100,\"format\":\"json\"," +
                "\"secret\":false,\"zk_encrypted\":true," +
                "\"created_at\":\"2024-01-15T10:30:00Z\",\"updated_at\":\"2024-01-15T10:30:00Z\"}]";
        server.enqueue(new MockResponse().setBody(json));

        try (Client client = Client.builder(baseUrl).build()) {
            KeyInfo info = client.info("app/config");

            assertThat(info.getKey()).isEqualTo("app/config");
            assertThat(info.isZkEncrypted()).isTrue();
        }
    }

    @Test
    void infoThrowsNotFoundWhenKeyNotInList() {
        server.enqueue(new MockResponse().setBody("[]"));

        try (Client client = Client.builder(baseUrl).build()) {
            assertThatThrownBy(() -> client.info("missing"))
                    .isInstanceOf(NotFoundError.class);
        }
    }

    @Test
    void pingReturnsTrue() {
        server.enqueue(new MockResponse().setBody("pong"));

        try (Client client = Client.builder(baseUrl).build()) {
            assertThat(client.ping()).isTrue();
        }
    }

    @Test
    void pingReturnsFalseOnError() {
        server.enqueue(new MockResponse().setResponseCode(500));

        try (Client client = Client.builder(baseUrl).build()) {
            assertThat(client.ping()).isFalse();
        }
    }

    @Test
    void authTokenSentInHeader() throws InterruptedException {
        server.enqueue(new MockResponse().setBody("value"));

        try (Client client = Client.builder(baseUrl).token("secret-token").build()) {
            client.get("key");

            RecordedRequest request = server.takeRequest();
            assertThat(request.getHeader("Authorization")).isEqualTo("Bearer secret-token");
        }
    }

    @Test
    void unauthorizedThrowsError() {
        server.enqueue(new MockResponse().setResponseCode(401));

        try (Client client = Client.builder(baseUrl).build()) {
            assertThatThrownBy(() -> client.get("key"))
                    .isInstanceOf(UnauthorizedError.class);
        }
    }

    @Test
    void forbiddenThrowsError() {
        server.enqueue(new MockResponse().setResponseCode(403));

        try (Client client = Client.builder(baseUrl).build()) {
            assertThatThrownBy(() -> client.get("key"))
                    .isInstanceOf(ForbiddenError.class);
        }
    }

    @Test
    void retryOnConnectionError() {
        // first request fails, second succeeds
        server.enqueue(new MockResponse().setSocketPolicy(okhttp3.mockwebserver.SocketPolicy.DISCONNECT_AFTER_REQUEST));
        server.enqueue(new MockResponse().setBody("success"));

        try (Client client = Client.builder(baseUrl)
                .retries(2)
                .retryDelay(Duration.ofMillis(10))
                .build()) {
            String value = client.get("key");
            assertThat(value).isEqualTo("success");
        }
    }

    @Test
    void emptyKeyRejected() {
        try (Client client = Client.builder(baseUrl).build()) {
            assertThatThrownBy(() -> client.get(""))
                    .isInstanceOf(StashException.class)
                    .hasMessageContaining("empty");

            assertThatThrownBy(() -> client.get(null))
                    .isInstanceOf(StashException.class);
        }
    }

    @Test
    void zkEncryptionAutoEncryptsOnSet() throws InterruptedException {
        server.enqueue(new MockResponse().setResponseCode(200));

        try (Client client = Client.builder(baseUrl)
                .zkKey("test-passphrase-16")
                .build()) {
            client.set("key", "secret value");

            RecordedRequest request = server.takeRequest();
            String body = request.getBody().readUtf8();
            assertThat(body).startsWith("$ZK$");
        }
    }

    @Test
    void zkEncryptionAutoDecryptsOnGet() {
        // create encrypted value
        ZKCrypto crypto = new ZKCrypto("test-passphrase-16");
        String encrypted = crypto.encrypt("secret value");
        server.enqueue(new MockResponse().setBody(encrypted));

        try (Client client = Client.builder(baseUrl)
                .zkKey("test-passphrase-16")
                .build()) {
            String value = client.get("key");
            assertThat(value).isEqualTo("secret value");
        }
    }

    @Test
    void zkEncryptionPassthroughPlaintext() {
        // non-ZK value returned as-is
        server.enqueue(new MockResponse().setBody("plain value"));

        try (Client client = Client.builder(baseUrl)
                .zkKey("test-passphrase-16")
                .build()) {
            String value = client.get("key");
            assertThat(value).isEqualTo("plain value");
        }
    }

    @Test
    void builderRejectsEmptyBaseUrl() {
        assertThatThrownBy(() -> Client.builder(""))
                .isInstanceOf(StashException.class);

        assertThatThrownBy(() -> Client.builder(null))
                .isInstanceOf(StashException.class);
    }

    @Test
    void pathEncodingPreservesSlashes() throws InterruptedException {
        server.enqueue(new MockResponse().setBody("value"));

        try (Client client = Client.builder(baseUrl).build()) {
            client.get("app/config/database");

            RecordedRequest request = server.takeRequest();
            assertThat(request.getPath()).isEqualTo("/kv/app/config/database");
        }
    }

    @Test
    void specialCharactersInKeyAreEncoded() throws InterruptedException {
        server.enqueue(new MockResponse().setBody("value"));

        try (Client client = Client.builder(baseUrl).build()) {
            client.get("app/config?special=true");

            RecordedRequest request = server.takeRequest();
            // '?' should be encoded, '/' preserved
            assertThat(request.getPath()).isEqualTo("/kv/app/config%3Fspecial%3Dtrue");
        }
    }

    @Test
    void spacesInKeyArePercentEncoded() throws InterruptedException {
        server.enqueue(new MockResponse().setBody("value"));

        try (Client client = Client.builder(baseUrl).build()) {
            client.get("app/my config/database");

            RecordedRequest request = server.takeRequest();
            // spaces must be %20 (URI encoding), not + (form encoding)
            assertThat(request.getPath()).isEqualTo("/kv/app/my%20config/database");
        }
    }

    @Test
    void listHandlesUnknownFormatAsText() {
        // server returns unknown format - should default to TEXT
        String json = "[{\"key\":\"app/config\",\"size\":100,\"format\":\"unknown-format\"," +
                "\"secret\":false,\"zk_encrypted\":false," +
                "\"created_at\":\"2024-01-15T10:30:00Z\",\"updated_at\":\"2024-01-15T10:30:00Z\"}]";
        server.enqueue(new MockResponse().setBody(json));

        try (Client client = Client.builder(baseUrl).build()) {
            List<KeyInfo> keys = client.list();

            assertThat(keys).hasSize(1);
            assertThat(keys.get(0).getFormat()).isEqualTo(Format.TEXT);
        }
    }
}
