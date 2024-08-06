package pl.mlodawski.security.pkcs11.exceptions;

/**
 * Exception indicating that a session logout has occurred.
 * This exception is thrown when a user's session has been forcefully logged out.
 * It is a subclass of RuntimeException.
 *
 * This exception can be used to handle session logout scenarios in an application.
 * When thrown, it provides information about the cause of the logout, which can be
 * obtained using the {@link Throwable#getCause()} method.
 *
 */
public class SessionLogoutException extends RuntimeException {
    public SessionLogoutException(String message, Throwable cause) {
        super(message, cause);
    }
}
