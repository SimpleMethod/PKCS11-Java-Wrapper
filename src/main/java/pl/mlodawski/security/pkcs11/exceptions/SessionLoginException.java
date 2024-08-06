package pl.mlodawski.security.pkcs11.exceptions;

/**
 * The SessionLoginException class represents an exception that is thrown when there is an error
 * during a session login process.
 *
 * This class extends the RuntimeException class, which makes it an unchecked exception. It allows
 * the exception to be thrown without the need for explicit handling or declaration.
 *
 * When a SessionLoginException is thrown, it provides a message and an optional cause that explains
 * the reason for the exception. The cause can be used to identify the underlying exception that
 * caused this exception to be thrown.
 *
 */
public class SessionLoginException extends RuntimeException {
    public SessionLoginException(String message, Throwable cause) {
        super(message, cause);
    }
}
