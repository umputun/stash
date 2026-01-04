package io.github.umputun.stash;

import io.github.umputun.stash.errors.*;
import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.google.gson.JsonDeserializer;
import com.google.gson.reflect.TypeToken;

import java.io.BufferedReader;
import java.io.Closeable;
import java.io.IOException;
import java.io.InputStreamReader;
import java.net.URI;
import java.net.URLEncoder;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.time.Instant;
import java.util.Iterator;
import java.util.List;
import java.util.NoSuchElementException;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;

/**
 * Client for the Stash key-value configuration service.
 * <p>
 * Use {@link #builder(String)} to create instances.
 * <p>
 * Example usage:
 * <pre>{@code
 * try (Client client = Client.builder("http://localhost:8080")
 *         .token("api-token")
 *         .zkKey("encryption-passphrase")
 *         .build()) {
 *     client.set("app/config", "{\"debug\": true}", Format.JSON);
 *     String value = client.get("app/config");
 * }
 * }</pre>
 */
public final class Client implements Closeable {

    private static final String HEADER_FORMAT = "X-Stash-Format";
    private static final String HEADER_AUTH = "Authorization";

    private final String baseUrl;
    private final ClientOptions options;
    private final HttpClient httpClient;
    private final ZKCrypto zkCrypto;
    private final Gson gson;

    private Client(String baseUrl, ClientOptions options) {
        this.baseUrl = baseUrl.endsWith("/") ? baseUrl.substring(0, baseUrl.length() - 1) : baseUrl;
        this.options = options;
        this.httpClient = HttpClient.newBuilder()
                .connectTimeout(options.getTimeout())
                .build();
        this.zkCrypto = options.isZkEnabled() ? new ZKCrypto(options.getZkKey()) : null;
        this.gson = createGson();
    }

    /**
     * Creates a new builder for the Client.
     *
     * @param baseUrl the base URL of the Stash server
     * @return a new builder
     */
    public static Builder builder(String baseUrl) {
        return new Builder(baseUrl);
    }

    /**
     * Retrieves the value for a key as a string.
     * If ZK encryption is enabled and the value is encrypted, it will be automatically decrypted.
     *
     * @param key the key to retrieve
     * @return the value
     * @throws NotFoundError   if the key does not exist
     * @throws DecryptionError if decryption fails
     */
    public String get(String key) {
        return new String(getBytes(key), StandardCharsets.UTF_8);
    }

    /**
     * Retrieves the value for a key as bytes.
     * If ZK encryption is enabled and the value is encrypted, it will be automatically decrypted.
     *
     * @param key the key to retrieve
     * @return the value as bytes
     * @throws NotFoundError   if the key does not exist
     * @throws DecryptionError if decryption fails
     */
    public byte[] getBytes(String key) {
        validateKey(key);
        byte[] value = doRequest("GET", "/kv/" + encodePath(key), null, null);

        // auto-decrypt if ZK enabled and value is encrypted
        if (zkCrypto != null && ZKCrypto.isZKEncrypted(value)) {
            String encrypted = new String(value, StandardCharsets.UTF_8);
            return zkCrypto.decryptBytes(encrypted);
        }
        return value;
    }

    /**
     * Retrieves the value for a key, returning a default if the key doesn't exist.
     *
     * @param key          the key to retrieve
     * @param defaultValue the default value to return if key doesn't exist
     * @return the value, or defaultValue if not found
     */
    public String getOrDefault(String key, String defaultValue) {
        try {
            return get(key);
        } catch (NotFoundError e) {
            return defaultValue;
        }
    }

    /**
     * Stores a value for a key with TEXT format.
     * If ZK encryption is enabled, the value will be automatically encrypted.
     *
     * @param key   the key
     * @param value the value to store
     */
    public void set(String key, String value) {
        set(key, value, Format.TEXT);
    }

    /**
     * Stores a value for a key with a specific format.
     * If ZK encryption is enabled, the value will be automatically encrypted.
     *
     * @param key    the key
     * @param value  the value to store
     * @param format the format for syntax highlighting
     */
    public void set(String key, String value, Format format) {
        validateKey(key);

        String toStore = value;
        // auto-encrypt if ZK enabled
        if (zkCrypto != null) {
            toStore = zkCrypto.encrypt(value);
        }

        doRequest("PUT", "/kv/" + encodePath(key), toStore.getBytes(StandardCharsets.UTF_8), format);
    }

    /**
     * Deletes a key.
     *
     * @param key the key to delete
     * @throws NotFoundError if the key does not exist
     */
    public void delete(String key) {
        validateKey(key);
        doRequest("DELETE", "/kv/" + encodePath(key), null, null);
    }

    /**
     * Lists all keys.
     *
     * @return list of key metadata
     */
    public List<KeyInfo> list() {
        return list("");
    }

    /**
     * Lists keys with a prefix filter.
     *
     * @param prefix the prefix to filter by (empty string for all)
     * @return list of key metadata
     */
    public List<KeyInfo> list(String prefix) {
        String path = "/kv/";
        if (prefix != null && !prefix.isEmpty()) {
            path += "?prefix=" + URLEncoder.encode(prefix, StandardCharsets.UTF_8);
        }

        byte[] response = doRequest("GET", path, null, null);
        String json = new String(response, StandardCharsets.UTF_8);
        return gson.fromJson(json, new TypeToken<List<KeyInfo>>() {}.getType());
    }

    /**
     * Gets metadata for a specific key.
     *
     * @param key the key
     * @return the key metadata
     * @throws NotFoundError if the key does not exist
     */
    public KeyInfo info(String key) {
        validateKey(key);
        List<KeyInfo> keys = list(key);
        for (KeyInfo info : keys) {
            if (key.equals(info.getKey())) {
                return info;
            }
        }
        throw new NotFoundError(key);
    }

    /**
     * Checks server health.
     *
     * @return true if server responds with "pong"
     */
    public boolean ping() {
        try {
            byte[] response = doRequest("GET", "/ping", null, null);
            return "pong".equals(new String(response, StandardCharsets.UTF_8));
        } catch (Exception e) {
            return false;
        }
    }

    /**
     * Subscribes to changes for an exact key.
     *
     * @param key the key to monitor
     * @return subscription that yields events
     * @throws StashException if key is empty
     */
    public Subscription subscribe(String key) {
        validateKey(key);
        String url = baseUrl + "/kv/subscribe/" + encodePath(key);
        return new SubscriptionImpl(url, options.getToken(), gson);
    }

    /**
     * Subscribes to changes for all keys with a prefix.
     *
     * @param prefix the prefix to monitor (e.g., "app" matches "app/config", "app/db")
     * @return subscription that yields events
     * @throws StashException if prefix is empty
     */
    public Subscription subscribePrefix(String prefix) {
        if (prefix == null || prefix.isEmpty()) {
            throw new StashException("prefix cannot be empty");
        }
        String url = baseUrl + "/kv/subscribe/" + encodePath(prefix) + "/*";
        return new SubscriptionImpl(url, options.getToken(), gson);
    }

    /**
     * Subscribes to changes for all keys.
     *
     * @return subscription that yields events
     */
    public Subscription subscribeAll() {
        String url = baseUrl + "/kv/subscribe/*";
        return new SubscriptionImpl(url, options.getToken(), gson);
    }

    @Override
    public void close() {
        // HttpClient doesn't need explicit closing in Java 11+
    }

    private byte[] doRequest(String method, String path, byte[] body, Format format) {
        int attempts = options.getRetries() + 1;
        Exception lastException = null;

        for (int attempt = 0; attempt < attempts; attempt++) {
            try {
                return executeRequest(method, path, body, format);
            } catch (ConnectionError e) {
                lastException = e;
                if (attempt < attempts - 1) {
                    sleep(calculateBackoff(attempt));
                }
            }
        }

        throw (ConnectionError) lastException;
    }

    private byte[] executeRequest(String method, String path, byte[] body, Format format) {
        try {
            HttpRequest.Builder requestBuilder = HttpRequest.newBuilder()
                    .uri(URI.create(baseUrl + path))
                    .timeout(options.getTimeout());

            // add auth header if token is set
            if (options.getToken() != null) {
                requestBuilder.header(HEADER_AUTH, "Bearer " + options.getToken());
            }

            // add format header if set
            if (format != null) {
                requestBuilder.header(HEADER_FORMAT, format.getValue());
            }

            // set method and body
            if (body != null) {
                requestBuilder.method(method, HttpRequest.BodyPublishers.ofByteArray(body));
            } else if ("PUT".equals(method) || "POST".equals(method)) {
                requestBuilder.method(method, HttpRequest.BodyPublishers.noBody());
            } else {
                requestBuilder.method(method, HttpRequest.BodyPublishers.noBody());
            }

            HttpResponse<byte[]> response = httpClient.send(
                    requestBuilder.build(),
                    HttpResponse.BodyHandlers.ofByteArray()
            );

            int status = response.statusCode();
            if (status >= 200 && status < 300) {
                return response.body();
            }

            // extract key from path for error messages
            String key = path.startsWith("/kv/") ? path.substring(4) : path;

            switch (status) {
                case 401:
                    throw new UnauthorizedError();
                case 403:
                    throw new ForbiddenError(key);
                case 404:
                    throw new NotFoundError(key);
                default:
                    String errorBody = new String(response.body(), StandardCharsets.UTF_8);
                    throw new StashException("HTTP " + status + ": " + errorBody);
            }
        } catch (StashException e) {
            throw e;
        } catch (java.net.ConnectException | java.net.SocketTimeoutException e) {
            throw new ConnectionError("connection failed: " + e.getMessage(), e);
        } catch (java.io.InterruptedIOException e) {
            throw new ConnectionError("request timeout", e);
        } catch (Exception e) {
            throw new ConnectionError("request failed: " + e.getMessage(), e);
        }
    }

    private Duration calculateBackoff(int attempt) {
        // exponential backoff: delay * 2^attempt
        long baseMs = options.getRetryDelay().toMillis();
        long backoffMs = baseMs * (1L << attempt);
        return Duration.ofMillis(Math.min(backoffMs, 30_000)); // cap at 30 seconds
    }

    private void sleep(Duration duration) {
        try {
            Thread.sleep(duration.toMillis());
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
    }

    private void validateKey(String key) {
        if (key == null || key.isEmpty()) {
            throw new StashException("key cannot be empty");
        }
    }

    private String encodePath(String path) {
        // encode each segment but preserve slashes
        // use URI encoding (spaces → %20) not form encoding (spaces → +)
        StringBuilder encoded = new StringBuilder();
        for (String segment : path.split("/", -1)) {
            if (encoded.length() > 0) {
                encoded.append("/");
            }
            // URLEncoder produces form encoding, need to fix spaces
            String formEncoded = URLEncoder.encode(segment, StandardCharsets.UTF_8);
            encoded.append(formEncoded.replace("+", "%20"));
        }
        return encoded.toString();
    }

    private static Gson createGson() {
        return new GsonBuilder()
                .registerTypeAdapter(Instant.class, (JsonDeserializer<Instant>) (json, type, ctx) -> {
                    String str = json.getAsString();
                    return Instant.parse(str);
                })
                .registerTypeAdapter(Format.class, (JsonDeserializer<Format>) (json, type, ctx) -> {
                    // default to TEXT for unknown formats (forward compatibility)
                    return Format.fromValue(json.getAsString());
                })
                .create();
    }

    /**
     * Builder for creating Client instances.
     */
    public static final class Builder {
        private final String baseUrl;
        private final ClientOptions.Builder optionsBuilder = ClientOptions.builder();

        private Builder(String baseUrl) {
            if (baseUrl == null || baseUrl.isEmpty()) {
                throw new StashException("baseUrl cannot be empty");
            }
            this.baseUrl = baseUrl;
        }

        /**
         * Sets the authentication token.
         *
         * @param token the bearer token
         * @return this builder
         */
        public Builder token(String token) {
            optionsBuilder.token(token);
            return this;
        }

        /**
         * Sets the request timeout.
         *
         * @param timeout the timeout duration
         * @return this builder
         */
        public Builder timeout(Duration timeout) {
            optionsBuilder.timeout(timeout);
            return this;
        }

        /**
         * Sets the number of retry attempts.
         *
         * @param retries the number of retries
         * @return this builder
         */
        public Builder retries(int retries) {
            optionsBuilder.retries(retries);
            return this;
        }

        /**
         * Sets the delay between retries.
         *
         * @param retryDelay the delay duration
         * @return this builder
         */
        public Builder retryDelay(Duration retryDelay) {
            optionsBuilder.retryDelay(retryDelay);
            return this;
        }

        /**
         * Enables zero-knowledge encryption with the given passphrase.
         *
         * @param zkKey the encryption passphrase (minimum 16 bytes UTF-8)
         * @return this builder
         */
        public Builder zkKey(String zkKey) {
            optionsBuilder.zkKey(zkKey);
            return this;
        }

        /**
         * Builds the Client instance.
         *
         * @return the configured client
         */
        public Client build() {
            return new Client(baseUrl, optionsBuilder.build());
        }
    }

    /**
     * Internal SSE subscription implementation with auto-reconnection.
     */
    private static class SubscriptionImpl implements Subscription {
        private final String url;
        private final String token;
        private final Gson gson;
        private final HttpClient httpClient;
        private final AtomicBoolean closed = new AtomicBoolean(false);
        private final BlockingQueue<SubscriptionEvent> queue = new LinkedBlockingQueue<>();
        private final Thread workerThread;

        SubscriptionImpl(String url, String token, Gson gson) {
            this.url = url;
            this.token = token;
            this.gson = gson;
            this.httpClient = HttpClient.newBuilder()
                    .connectTimeout(Duration.ofSeconds(30))
                    .build();

            // start background thread to read SSE events
            this.workerThread = new Thread(this::runWithReconnect, "stash-subscription");
            this.workerThread.setDaemon(true);
            this.workerThread.start();
        }

        private void runWithReconnect() {
            long delay = 1000; // 1s initial

            while (!closed.get()) {
                try {
                    streamEvents();
                    delay = 1000; // reset on successful connection
                } catch (Exception e) {
                    if (closed.get()) {
                        break;
                    }
                    try {
                        Thread.sleep(delay);
                    } catch (InterruptedException ie) {
                        Thread.currentThread().interrupt();
                        break;
                    }
                    delay = Math.min(delay * 2, 30_000); // max 30s
                }
            }
        }

        private void streamEvents() throws IOException, InterruptedException {
            HttpRequest.Builder requestBuilder = HttpRequest.newBuilder()
                    .uri(URI.create(url))
                    .GET();

            if (token != null) {
                requestBuilder.header("Authorization", "Bearer " + token);
            }

            HttpResponse<java.io.InputStream> response = httpClient.send(
                    requestBuilder.build(),
                    HttpResponse.BodyHandlers.ofInputStream()
            );

            if (response.statusCode() != 200) {
                response.body().close();
                throw new IOException("HTTP " + response.statusCode());
            }

            try (BufferedReader reader = new BufferedReader(
                    new InputStreamReader(response.body(), StandardCharsets.UTF_8))) {

                String eventType = "";
                String eventData = "";

                String line;
                while (!closed.get() && (line = reader.readLine()) != null) {
                    if (line.startsWith("event:")) {
                        eventType = line.substring(6).trim();
                    } else if (line.startsWith("data:")) {
                        String data = line.substring(5).trim();
                        eventData = eventData.isEmpty() ? data : eventData + "\n" + data;
                    } else if (line.isEmpty() && !eventData.isEmpty()) {
                        // end of event
                        if ("change".equals(eventType)) {
                            try {
                                SubscriptionEvent event = gson.fromJson(eventData, SubscriptionEvent.class);
                                queue.put(event);
                            } catch (Exception e) {
                                // ignore malformed events
                            }
                        }
                        eventType = "";
                        eventData = "";
                    }
                }
            }
        }

        @Override
        public Iterator<SubscriptionEvent> iterator() {
            return new Iterator<SubscriptionEvent>() {
                private SubscriptionEvent next = null;

                @Override
                public boolean hasNext() {
                    if (closed.get() && queue.isEmpty()) {
                        return false;
                    }
                    if (next != null) {
                        return true;
                    }
                    try {
                        // poll with timeout to allow checking closed flag
                        while (!closed.get()) {
                            next = queue.poll(100, TimeUnit.MILLISECONDS);
                            if (next != null) {
                                return true;
                            }
                        }
                        // drain remaining queue after close
                        next = queue.poll();
                        return next != null;
                    } catch (InterruptedException e) {
                        Thread.currentThread().interrupt();
                        return false;
                    }
                }

                @Override
                public SubscriptionEvent next() {
                    if (next == null && !hasNext()) {
                        throw new NoSuchElementException();
                    }
                    SubscriptionEvent result = next;
                    next = null;
                    return result;
                }
            };
        }

        @Override
        public void close() {
            closed.set(true);
            workerThread.interrupt();
            try {
                workerThread.join(1000); // wait up to 1 second for thread to terminate
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
            }
        }
    }
}
