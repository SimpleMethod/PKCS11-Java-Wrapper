package pl.mlodawski.security.pkcs11.exceptions;

/**
 * Exception thrown when hardware digest (hash) operation fails.
 */
public class DigestException extends RuntimeException {
    public DigestException(String message, Throwable cause) {
        super(message, cause);
    }
}
