package pl.mlodawski.security.pkcs11.exceptions;

/**
 * {@code SessionResetException} is an exception that indicates a session reset error.
 *
 * This exception is usually thrown when the session needs to be reset due to some error condition.
 * It provides a way to communicate the error message along with the cause of the exception.
 *
 */
public class SessionResetException extends RuntimeException {
    public SessionResetException(String message, Throwable cause) {
        super(message, cause);
    }
}
