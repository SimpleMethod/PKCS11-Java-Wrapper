package pl.mlodawski.security.pkcs11.exceptions;

/**
 * The SigningInitializationException class is a runtime exception that is thrown when an error occurs during the
 * initialization of signing functionality.
 *
 * This exception is intended to be used when there is an issue in the initialization process that prevents signing
 * functionality from working properly. It extends the RuntimeException class, meaning that it is an unchecked exception.
 *
 * When creating an instance of SigningInitializationException, a descriptive error message and the underlying cause of
 * the exception can be provided.
 */
public class SigningInitializationException extends RuntimeException {
    public SigningInitializationException(String message, Throwable cause) {
        super(message, cause);
    }
}
