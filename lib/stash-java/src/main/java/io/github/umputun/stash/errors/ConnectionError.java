package io.github.umputun.stash.errors;

/**
 * Thrown when a network connection fails.
 */
public class ConnectionError extends StashException {

    /**
     * Creates a new ConnectionError.
     *
     * @param message the error message
     */
    public ConnectionError(String message) {
        super(message);
    }

    /**
     * Creates a new ConnectionError with a cause.
     *
     * @param message the error message
     * @param cause   the underlying cause
     */
    public ConnectionError(String message, Throwable cause) {
        super(message, cause);
    }
}
