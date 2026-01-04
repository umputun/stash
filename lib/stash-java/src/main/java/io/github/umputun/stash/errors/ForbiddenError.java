package io.github.umputun.stash.errors;

/**
 * Thrown when access is denied (HTTP 403).
 */
public class ForbiddenError extends StashException {

    private final String key;

    /**
     * Creates a new ForbiddenError.
     *
     * @param key the key that access was denied to
     */
    public ForbiddenError(String key) {
        super("forbidden: access denied for key: " + key);
        this.key = key;
    }

    /**
     * Returns the key that access was denied to.
     *
     * @return the key
     */
    public String getKey() {
        return key;
    }
}
