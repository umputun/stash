package io.github.umputun.stash.errors;

/**
 * Thrown when ZK decryption fails.
 */
public class DecryptionError extends StashException {

    /**
     * Creates a new DecryptionError.
     *
     * @param message the error message
     */
    public DecryptionError(String message) {
        super(message);
    }

    /**
     * Creates a new DecryptionError with a cause.
     *
     * @param message the error message
     * @param cause   the underlying cause
     */
    public DecryptionError(String message, Throwable cause) {
        super(message, cause);
    }
}
