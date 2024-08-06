package pl.mlodawski.security.pkcs11.exceptions;

/**
 * Exception thrown when PKCS#11 initialization fails.
 */
public class PKCS11InitializationException extends RuntimeException {
    public PKCS11InitializationException(String message, Throwable cause) {
        super(message, cause);
    }
}
