package pl.mlodawski.security.pkcs11.exceptions;

/**
 * A runtime exception that is thrown when an error occurs during signing.
 */
public class SigningException extends RuntimeException {
    public SigningException(String message, Throwable cause) {
        super(message, cause);
    }
}
