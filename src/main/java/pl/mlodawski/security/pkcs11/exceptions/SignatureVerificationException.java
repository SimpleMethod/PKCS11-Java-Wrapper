package pl.mlodawski.security.pkcs11.exceptions;

/**
 * Represents an exception that occurs when a signature verification fails.
 * This exception is a subclass of RuntimeException.
 */
public class SignatureVerificationException extends RuntimeException {
    public SignatureVerificationException(String message, Throwable cause) {
        super(message, cause);
    }
}
