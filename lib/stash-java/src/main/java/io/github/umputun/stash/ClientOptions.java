package io.github.umputun.stash;

import io.github.umputun.stash.errors.StashException;

import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.Objects;

/**
 * Configuration options for the Stash client.
 * Use {@link #builder()} to create instances.
 */
public final class ClientOptions {

    /** default timeout for HTTP requests */
    public static final Duration DEFAULT_TIMEOUT = Duration.ofSeconds(30);

    /** default number of retries */
    public static final int DEFAULT_RETRIES = 3;

    /** default delay between retries */
    public static final Duration DEFAULT_RETRY_DELAY = Duration.ofMillis(100);

    private final String token;
    private final Duration timeout;
    private final int retries;
    private final Duration retryDelay;
    private final String zkKey;

    private ClientOptions(Builder builder) {
        this.token = builder.token;
        this.timeout = builder.timeout;
        this.retries = builder.retries;
        this.retryDelay = builder.retryDelay;
        this.zkKey = builder.zkKey;
    }

    /**
     * Creates a new builder for ClientOptions.
     *
     * @return a new builder
     */
    public static Builder builder() {
        return new Builder();
    }

    /**
     * Returns the authentication token, or null if not set.
     *
     * @return the token
     */
    public String getToken() {
        return token;
    }

    /**
     * Returns the request timeout.
     *
     * @return the timeout
     */
    public Duration getTimeout() {
        return timeout;
    }

    /**
     * Returns the number of retry attempts.
     *
     * @return the retries count
     */
    public int getRetries() {
        return retries;
    }

    /**
     * Returns the delay between retries.
     *
     * @return the retry delay
     */
    public Duration getRetryDelay() {
        return retryDelay;
    }

    /**
     * Returns the ZK encryption key, or null if not set.
     *
     * @return the ZK key
     */
    public String getZkKey() {
        return zkKey;
    }

    /**
     * Checks if ZK encryption is enabled.
     *
     * @return true if ZK key is set
     */
    public boolean isZkEnabled() {
        return zkKey != null;
    }

    /**
     * Builder for ClientOptions.
     */
    public static final class Builder {
        private String token;
        private Duration timeout = DEFAULT_TIMEOUT;
        private int retries = DEFAULT_RETRIES;
        private Duration retryDelay = DEFAULT_RETRY_DELAY;
        private String zkKey;

        private Builder() {
        }

        /**
         * Sets the authentication token for API requests.
         *
         * @param token the bearer token
         * @return this builder
         */
        public Builder token(String token) {
            this.token = token;
            return this;
        }

        /**
         * Sets the request timeout.
         *
         * @param timeout the timeout duration
         * @return this builder
         * @throws StashException if timeout is null or not positive
         */
        public Builder timeout(Duration timeout) {
            Objects.requireNonNull(timeout, "timeout cannot be null");
            if (timeout.isNegative() || timeout.isZero()) {
                throw new StashException("timeout must be positive");
            }
            this.timeout = timeout;
            return this;
        }

        /**
         * Sets the number of retry attempts for failed requests.
         *
         * @param retries the number of retries (0 or more)
         * @return this builder
         * @throws StashException if retries is negative
         */
        public Builder retries(int retries) {
            if (retries < 0) {
                throw new StashException("retries cannot be negative");
            }
            this.retries = retries;
            return this;
        }

        /**
         * Sets the delay between retry attempts.
         *
         * @param retryDelay the delay duration
         * @return this builder
         * @throws StashException if retryDelay is null or negative
         */
        public Builder retryDelay(Duration retryDelay) {
            Objects.requireNonNull(retryDelay, "retryDelay cannot be null");
            if (retryDelay.isNegative()) {
                throw new StashException("retryDelay cannot be negative");
            }
            this.retryDelay = retryDelay;
            return this;
        }

        /**
         * Sets the passphrase for zero-knowledge encryption.
         * Values will be automatically encrypted before sending and decrypted after receiving.
         *
         * @param zkKey the encryption passphrase (minimum 16 bytes UTF-8)
         * @return this builder
         * @throws StashException if zkKey is too short
         */
        public Builder zkKey(String zkKey) {
            if (zkKey != null) {
                byte[] bytes = zkKey.getBytes(StandardCharsets.UTF_8);
                if (bytes.length < ZKCrypto.MIN_PASSPHRASE_BYTES) {
                    throw new StashException("zkKey must be at least " + ZKCrypto.MIN_PASSPHRASE_BYTES + " bytes");
                }
            }
            this.zkKey = zkKey;
            return this;
        }

        /**
         * Builds the ClientOptions instance.
         *
         * @return the configured options
         */
        public ClientOptions build() {
            return new ClientOptions(this);
        }
    }
}
