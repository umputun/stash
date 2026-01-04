package io.github.umputun.stash;

import java.util.Objects;

/**
 * Event from SSE subscription.
 */
public final class SubscriptionEvent {

    private final String key;
    private final String action;
    private final String timestamp;

    /**
     * Creates a new subscription event.
     *
     * @param key       the key that changed
     * @param action    the action: create, update, or delete
     * @param timestamp RFC3339 timestamp when the change occurred
     */
    public SubscriptionEvent(String key, String action, String timestamp) {
        this.key = key;
        this.action = action;
        this.timestamp = timestamp;
    }

    /**
     * Returns the key that changed.
     *
     * @return the key
     */
    public String getKey() {
        return key;
    }

    /**
     * Returns the action performed.
     *
     * @return the action: create, update, or delete
     */
    public String getAction() {
        return action;
    }

    /**
     * Returns the timestamp when the change occurred.
     *
     * @return RFC3339 formatted timestamp
     */
    public String getTimestamp() {
        return timestamp;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        SubscriptionEvent that = (SubscriptionEvent) o;
        return Objects.equals(key, that.key) &&
                Objects.equals(action, that.action) &&
                Objects.equals(timestamp, that.timestamp);
    }

    @Override
    public int hashCode() {
        return Objects.hash(key, action, timestamp);
    }

    @Override
    public String toString() {
        return "SubscriptionEvent{" +
                "key='" + key + '\'' +
                ", action='" + action + '\'' +
                ", timestamp='" + timestamp + '\'' +
                '}';
    }
}
