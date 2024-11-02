package pl.mlodawski.security.pkcs11.exceptions;


/**
 * Exception thrown to indicate that a device is not ready to perform an operation.
 * This might be due to the device being in an uninitialized state,
 * not powered on, or otherwise unavailable for the requested operation.
 *
 * The exception provides a message to describe the specific issue and a cause
 * to indicate the underlying problem that triggered this exception.
 */
public class DeviceNotReadyException extends RuntimeException {
    public DeviceNotReadyException(String message, Throwable cause) {
        super(message, cause);
    }
}
