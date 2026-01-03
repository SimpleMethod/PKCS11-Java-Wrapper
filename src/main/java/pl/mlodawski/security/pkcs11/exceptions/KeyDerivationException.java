package pl.mlodawski.security.pkcs11.exceptions;

/**
 * Exception thrown when key derivation operation fails.
 */
public class KeyDerivationException extends RuntimeException {
    public KeyDerivationException(String message, Throwable cause) {
        super(message, cause);
    }
}
