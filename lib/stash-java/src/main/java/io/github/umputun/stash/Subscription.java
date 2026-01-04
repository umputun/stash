package io.github.umputun.stash;

import java.util.Iterator;

/**
 * SSE subscription with iteration support and auto-reconnection.
 * <p>
 * Use with try-with-resources for automatic cleanup:
 * <pre>{@code
 * try (Subscription sub = client.subscribe("app/config")) {
 *     for (SubscriptionEvent event : sub) {
 *         System.out.println(event.getAction() + ": " + event.getKey());
 *     }
 * }
 * }</pre>
 * <p>
 * The subscription automatically reconnects on connection failure with
 * exponential backoff (1s initial, 30s max).
 */
public interface Subscription extends AutoCloseable, Iterable<SubscriptionEvent> {

    /**
     * Returns an iterator over subscription events.
     * The iterator blocks waiting for new events until the subscription is closed.
     *
     * @return iterator over events
     */
    @Override
    Iterator<SubscriptionEvent> iterator();

    /**
     * Closes the subscription and stops receiving events.
     * Safe to call multiple times.
     */
    @Override
    void close();
}
