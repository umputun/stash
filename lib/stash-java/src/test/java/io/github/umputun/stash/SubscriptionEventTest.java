package io.github.umputun.stash;

import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

class SubscriptionEventTest {

    @Test
    void constructorAndGetters() {
        SubscriptionEvent event = new SubscriptionEvent("app/config", "update", "2025-01-03T10:00:00Z");

        assertThat(event.getKey()).isEqualTo("app/config");
        assertThat(event.getAction()).isEqualTo("update");
        assertThat(event.getTimestamp()).isEqualTo("2025-01-03T10:00:00Z");
    }

    @Test
    void equalsAndHashCode() {
        SubscriptionEvent event1 = new SubscriptionEvent("app/config", "update", "2025-01-03T10:00:00Z");
        SubscriptionEvent event2 = new SubscriptionEvent("app/config", "update", "2025-01-03T10:00:00Z");
        SubscriptionEvent event3 = new SubscriptionEvent("app/other", "update", "2025-01-03T10:00:00Z");

        assertThat(event1).isEqualTo(event2);
        assertThat(event1.hashCode()).isEqualTo(event2.hashCode());
        assertThat(event1).isNotEqualTo(event3);
    }

    @Test
    void toStringContainsAllFields() {
        SubscriptionEvent event = new SubscriptionEvent("app/config", "delete", "2025-01-03T10:00:00Z");

        String str = event.toString();
        assertThat(str).contains("app/config");
        assertThat(str).contains("delete");
        assertThat(str).contains("2025-01-03T10:00:00Z");
    }
}
