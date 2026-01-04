package io.github.umputun.stash;

import org.junit.jupiter.api.Test;

import java.time.Instant;

import static org.assertj.core.api.Assertions.assertThat;

class KeyInfoTest {

    @Test
    void constructorAndGetters() {
        Instant created = Instant.parse("2024-01-15T10:30:00Z");
        Instant updated = Instant.parse("2024-01-15T11:00:00Z");

        KeyInfo info = new KeyInfo(
                "app/config",
                1024,
                Format.JSON,
                false,
                true,
                created,
                updated
        );

        assertThat(info.getKey()).isEqualTo("app/config");
        assertThat(info.getSize()).isEqualTo(1024);
        assertThat(info.getFormat()).isEqualTo(Format.JSON);
        assertThat(info.isSecret()).isFalse();
        assertThat(info.isZkEncrypted()).isTrue();
        assertThat(info.getCreatedAt()).isEqualTo(created);
        assertThat(info.getUpdatedAt()).isEqualTo(updated);
    }

    @Test
    void equalsAndHashCode() {
        Instant now = Instant.now();

        KeyInfo info1 = new KeyInfo("key", 100, Format.TEXT, false, false, now, now);
        KeyInfo info2 = new KeyInfo("key", 100, Format.TEXT, false, false, now, now);
        KeyInfo info3 = new KeyInfo("other", 100, Format.TEXT, false, false, now, now);

        assertThat(info1).isEqualTo(info2);
        assertThat(info1.hashCode()).isEqualTo(info2.hashCode());
        assertThat(info1).isNotEqualTo(info3);
    }

    @Test
    void toStringContainsAllFields() {
        KeyInfo info = new KeyInfo("test", 50, Format.YAML, true, false, null, null);

        String str = info.toString();
        assertThat(str).contains("key='test'");
        assertThat(str).contains("size=50");
        assertThat(str).contains("format=yaml");
        assertThat(str).contains("secret=true");
        assertThat(str).contains("zkEncrypted=false");
    }
}
