package pl.mlodawski.security.pkcs11.exceptions;

/**
 * Exception thrown for failures during byte conversion.
 *
 * This exception extends the {@link RuntimeException}, indicating that it is an unchecked exception. It should be used
 * to handle failures or errors that occur during byte conversion operations.
 *
 */
public class ByteConversionException extends RuntimeException {
    public ByteConversionException(String message, Throwable cause) {
        super(message, cause);
    }
}
