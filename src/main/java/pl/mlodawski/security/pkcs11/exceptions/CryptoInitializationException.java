package pl.mlodawski.security.pkcs11.exceptions;

/**
 * CryptoInitializationException is a custom exception class that is thrown when there is an error during crypto initialization.
 */
public class CryptoInitializationException extends RuntimeException {
    public CryptoInitializationException(String message, Throwable cause) {
        super(message, cause);
    }
}
