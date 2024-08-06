package pl.mlodawski.security.pkcs11.exceptions;

/**
 * This class represents an exception thrown when there is an error while closing a session.
 */
public class SessionCloseException extends RuntimeException {
    public SessionCloseException(String message, Throwable cause) {
        super(message, cause);
    }
}
