package com.github.umputun.stash.errors;

/**
 * Base exception for all Stash client errors.
 */
public class StashException extends RuntimeException {

    /**
     * Creates a new StashException with a message.
     *
     * @param message the error message
     */
    public StashException(String message) {
        super(message);
    }

    /**
     * Creates a new StashException with a message and cause.
     *
     * @param message the error message
     * @param cause   the underlying cause
     */
    public StashException(String message, Throwable cause) {
        super(message, cause);
    }
}
