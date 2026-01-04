package io.github.umputun.stash;

import io.github.umputun.stash.errors.StashException;
import okhttp3.mockwebserver.MockResponse;
import okhttp3.mockwebserver.MockWebServer;
import okhttp3.mockwebserver.RecordedRequest;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.TimeUnit;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class SubscriptionTest {

    private MockWebServer server;
    private Client client;

    @BeforeEach
    void setUp() throws IOException {
        server = new MockWebServer();
        server.start();
        client = Client.builder(server.url("/").toString()).build();
    }

    @AfterEach
    void tearDown() throws IOException {
        client.close();
        server.shutdown();
    }

    @Test
    void subscribeReturnsSubscription() {
        Subscription sub = client.subscribe("app/config");
        assertThat(sub).isNotNull();
        sub.close();
    }

    @Test
    void subscribeThrowsOnEmptyKey() {
        assertThatThrownBy(() -> client.subscribe(""))
                .isInstanceOf(StashException.class)
                .hasMessageContaining("key cannot be empty");
    }

    @Test
    void subscribeThrowsOnNullKey() {
        assertThatThrownBy(() -> client.subscribe(null))
                .isInstanceOf(StashException.class)
                .hasMessageContaining("key cannot be empty");
    }

    @Test
    void subscribePrefixReturnsSubscription() {
        Subscription sub = client.subscribePrefix("app");
        assertThat(sub).isNotNull();
        sub.close();
    }

    @Test
    void subscribePrefixThrowsOnEmptyPrefix() {
        assertThatThrownBy(() -> client.subscribePrefix(""))
                .isInstanceOf(StashException.class)
                .hasMessageContaining("prefix cannot be empty");
    }

    @Test
    void subscribeAllReturnsSubscription() {
        Subscription sub = client.subscribeAll();
        assertThat(sub).isNotNull();
        sub.close();
    }

    @Test
    void closeCanBeCalledMultipleTimes() {
        Subscription sub = client.subscribe("test");
        sub.close();
        sub.close();
        sub.close();
    }

    @Test
    void subscriptionIteratorReturnsEvents() throws Exception {
        String sseData = "event:change\n" +
                "data:{\"key\":\"app/config\",\"action\":\"update\",\"timestamp\":\"2025-01-03T10:00:00Z\"}\n\n" +
                "event:change\n" +
                "data:{\"key\":\"app/config\",\"action\":\"delete\",\"timestamp\":\"2025-01-03T10:01:00Z\"}\n\n";

        server.enqueue(new MockResponse()
                .setBody(sseData)
                .setHeader("Content-Type", "text/event-stream"));

        List<SubscriptionEvent> events = new ArrayList<>();
        try (Subscription sub = client.subscribe("app/config")) {
            for (SubscriptionEvent event : sub) {
                events.add(event);
                if (events.size() >= 2) {
                    break;
                }
            }
        }

        assertThat(events).hasSize(2);
        assertThat(events.get(0).getKey()).isEqualTo("app/config");
        assertThat(events.get(0).getAction()).isEqualTo("update");
        assertThat(events.get(0).getTimestamp()).isEqualTo("2025-01-03T10:00:00Z");
        assertThat(events.get(1).getKey()).isEqualTo("app/config");
        assertThat(events.get(1).getAction()).isEqualTo("delete");
    }

    @Test
    void subscriptionIgnoresNonChangeEvents() throws Exception {
        String sseData = "event:heartbeat\n" +
                "data:ping\n\n" +
                "event:change\n" +
                "data:{\"key\":\"test\",\"action\":\"create\",\"timestamp\":\"2025-01-03T10:00:00Z\"}\n\n" +
                "event:status\n" +
                "data:connected\n\n";

        server.enqueue(new MockResponse()
                .setBody(sseData)
                .setHeader("Content-Type", "text/event-stream"));

        List<SubscriptionEvent> events = new ArrayList<>();
        try (Subscription sub = client.subscribe("test")) {
            for (SubscriptionEvent event : sub) {
                events.add(event);
                break;
            }
        }

        assertThat(events).hasSize(1);
        assertThat(events.get(0).getKey()).isEqualTo("test");
        assertThat(events.get(0).getAction()).isEqualTo("create");
    }

    @Test
    void subscriptionSendsAuthToken() throws Exception {
        Client authClient = Client.builder(server.url("/").toString())
                .token("test-token")
                .build();

        server.enqueue(new MockResponse()
                .setBody("event:change\ndata:{\"key\":\"k\",\"action\":\"update\",\"timestamp\":\"2025-01-03T10:00:00Z\"}\n\n")
                .setHeader("Content-Type", "text/event-stream"));

        try (Subscription sub = authClient.subscribe("test")) {
            for (SubscriptionEvent event : sub) {
                break;
            }
        }

        RecordedRequest request = server.takeRequest(1, TimeUnit.SECONDS);
        assertThat(request).isNotNull();
        assertThat(request.getHeader("Authorization")).isEqualTo("Bearer test-token");

        authClient.close();
    }

    @Test
    void subscribeConstructsCorrectUrl() throws Exception {
        server.enqueue(new MockResponse()
                .setBody("event:change\ndata:{\"key\":\"k\",\"action\":\"update\",\"timestamp\":\"2025-01-03T10:00:00Z\"}\n\n")
                .setHeader("Content-Type", "text/event-stream"));

        try (Subscription sub = client.subscribe("app/config")) {
            for (SubscriptionEvent event : sub) {
                break;
            }
        }

        RecordedRequest request = server.takeRequest(1, TimeUnit.SECONDS);
        assertThat(request).isNotNull();
        assertThat(request.getPath()).isEqualTo("/kv/subscribe/app/config");
    }

    @Test
    void subscribePrefixConstructsCorrectUrl() throws Exception {
        server.enqueue(new MockResponse()
                .setBody("event:change\ndata:{\"key\":\"k\",\"action\":\"update\",\"timestamp\":\"2025-01-03T10:00:00Z\"}\n\n")
                .setHeader("Content-Type", "text/event-stream"));

        try (Subscription sub = client.subscribePrefix("app")) {
            for (SubscriptionEvent event : sub) {
                break;
            }
        }

        RecordedRequest request = server.takeRequest(1, TimeUnit.SECONDS);
        assertThat(request).isNotNull();
        assertThat(request.getPath()).isEqualTo("/kv/subscribe/app/*");
    }

    @Test
    void subscribeAllConstructsCorrectUrl() throws Exception {
        server.enqueue(new MockResponse()
                .setBody("event:change\ndata:{\"key\":\"k\",\"action\":\"update\",\"timestamp\":\"2025-01-03T10:00:00Z\"}\n\n")
                .setHeader("Content-Type", "text/event-stream"));

        try (Subscription sub = client.subscribeAll()) {
            for (SubscriptionEvent event : sub) {
                break;
            }
        }

        RecordedRequest request = server.takeRequest(1, TimeUnit.SECONDS);
        assertThat(request).isNotNull();
        assertThat(request.getPath()).isEqualTo("/kv/subscribe/*");
    }
}
