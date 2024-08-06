package pl.mlodawski.security.pkcs11.exceptions;

/**
 * This class represents an exception that is thrown when there is an error during encryption.
 * It extends the RuntimeException class, making it an unchecked exception.
 *
 */
public class EncryptionException extends RuntimeException {
    public EncryptionException(String message, Throwable cause) {
        super(message, cause);
    }
}
