package com.github.umputun.stash.errors;

/**
 * Thrown when a requested key is not found (HTTP 404).
 */
public class NotFoundError extends StashException {

    private final String key;

    /**
     * Creates a new NotFoundError.
     *
     * @param key the key that was not found
     */
    public NotFoundError(String key) {
        super("key not found: " + key);
        this.key = key;
    }

    /**
     * Returns the key that was not found.
     *
     * @return the key
     */
    public String getKey() {
        return key;
    }
}
