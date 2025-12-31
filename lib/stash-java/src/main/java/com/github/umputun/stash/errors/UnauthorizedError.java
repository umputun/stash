package com.github.umputun.stash.errors;

/**
 * Thrown when authentication fails (HTTP 401).
 */
public class UnauthorizedError extends StashException {

    /**
     * Creates a new UnauthorizedError.
     */
    public UnauthorizedError() {
        super("unauthorized: missing or invalid token");
    }

    /**
     * Creates a new UnauthorizedError with a custom message.
     *
     * @param message the error message
     */
    public UnauthorizedError(String message) {
        super(message);
    }
}
