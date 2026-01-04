package io.github.umputun.stash;

import io.github.umputun.stash.errors.StashException;
import org.junit.jupiter.api.Test;

import java.time.Duration;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class ClientOptionsTest {

    @Test
    void defaultValues() {
        ClientOptions options = ClientOptions.builder().build();

        assertThat(options.getToken()).isNull();
        assertThat(options.getTimeout()).isEqualTo(Duration.ofSeconds(30));
        assertThat(options.getRetries()).isEqualTo(3);
        assertThat(options.getRetryDelay()).isEqualTo(Duration.ofMillis(100));
        assertThat(options.getZkKey()).isNull();
        assertThat(options.isZkEnabled()).isFalse();
    }

    @Test
    void customValues() {
        ClientOptions options = ClientOptions.builder()
                .token("test-token")
                .timeout(Duration.ofSeconds(60))
                .retries(5)
                .retryDelay(Duration.ofMillis(500))
                .zkKey("test-zk-key-16bytes")
                .build();

        assertThat(options.getToken()).isEqualTo("test-token");
        assertThat(options.getTimeout()).isEqualTo(Duration.ofSeconds(60));
        assertThat(options.getRetries()).isEqualTo(5);
        assertThat(options.getRetryDelay()).isEqualTo(Duration.ofMillis(500));
        assertThat(options.getZkKey()).isEqualTo("test-zk-key-16bytes");
        assertThat(options.isZkEnabled()).isTrue();
    }

    @Test
    void timeoutValidation() {
        assertThatThrownBy(() -> ClientOptions.builder().timeout(null))
                .isInstanceOf(NullPointerException.class);

        assertThatThrownBy(() -> ClientOptions.builder().timeout(Duration.ZERO))
                .isInstanceOf(StashException.class)
                .hasMessageContaining("positive");

        assertThatThrownBy(() -> ClientOptions.builder().timeout(Duration.ofSeconds(-1)))
                .isInstanceOf(StashException.class)
                .hasMessageContaining("positive");
    }

    @Test
    void retriesValidation() {
        assertThatThrownBy(() -> ClientOptions.builder().retries(-1))
                .isInstanceOf(StashException.class)
                .hasMessageContaining("negative");

        // zero retries is valid
        ClientOptions options = ClientOptions.builder().retries(0).build();
        assertThat(options.getRetries()).isZero();
    }

    @Test
    void retryDelayValidation() {
        assertThatThrownBy(() -> ClientOptions.builder().retryDelay(null))
                .isInstanceOf(NullPointerException.class);

        assertThatThrownBy(() -> ClientOptions.builder().retryDelay(Duration.ofSeconds(-1)))
                .isInstanceOf(StashException.class)
                .hasMessageContaining("negative");

        // zero delay is valid
        ClientOptions options = ClientOptions.builder().retryDelay(Duration.ZERO).build();
        assertThat(options.getRetryDelay()).isEqualTo(Duration.ZERO);
    }

    @Test
    void zkKeyValidation() {
        // too short
        assertThatThrownBy(() -> ClientOptions.builder().zkKey("short"))
                .isInstanceOf(StashException.class)
                .hasMessageContaining("16 bytes");

        // null is valid (disables ZK)
        ClientOptions options = ClientOptions.builder().zkKey(null).build();
        assertThat(options.getZkKey()).isNull();
        assertThat(options.isZkEnabled()).isFalse();

        // exactly 16 bytes
        options = ClientOptions.builder().zkKey("exactly-16-bytes").build();
        assertThat(options.isZkEnabled()).isTrue();
    }

    @Test
    void builderIsReusable() {
        ClientOptions.Builder builder = ClientOptions.builder()
                .token("token1")
                .retries(1);

        ClientOptions options1 = builder.build();
        ClientOptions options2 = builder.token("token2").retries(2).build();

        assertThat(options1.getToken()).isEqualTo("token1");
        assertThat(options1.getRetries()).isEqualTo(1);
        assertThat(options2.getToken()).isEqualTo("token2");
        assertThat(options2.getRetries()).isEqualTo(2);
    }
}
