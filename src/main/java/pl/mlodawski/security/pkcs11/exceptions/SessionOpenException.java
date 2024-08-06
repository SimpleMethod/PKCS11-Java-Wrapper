package pl.mlodawski.security.pkcs11.exceptions;

/**
 * Exception thrown when the session failed to open.
 * This exception is a subclass of {@link RuntimeException}.
 * It provides a way to handle errors related to session opening in a convenient and standardized manner.
 */
public class SessionOpenException extends RuntimeException {
    public SessionOpenException(String message, Throwable cause) {
        super(message, cause);
    }
}
