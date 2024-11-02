package pl.mlodawski.security.pkcs11.exceptions;


/**
 * DeviceManagerException is a custom exception that extends RuntimeException.
 * This exception is used to handle errors related to device management operations.
 * The exception can capture an error message and a cause for the exception.
 */
public class DeviceManagerException extends RuntimeException {
    public DeviceManagerException(String message, Throwable cause) {
        super(message, cause);
    }
}
