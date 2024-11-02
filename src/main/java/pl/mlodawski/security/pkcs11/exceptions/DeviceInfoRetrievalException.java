package pl.mlodawski.security.pkcs11.exceptions;


/**
 * Exception thrown when there is a failure in retrieving device information.
 *
 * This exception is a specialized RuntimeException that takes a
 * message and a cause to provide more context about the error.
 */
public class DeviceInfoRetrievalException extends RuntimeException {
    public DeviceInfoRetrievalException(String message, Throwable cause) {
        super(message, cause);
    }
}
