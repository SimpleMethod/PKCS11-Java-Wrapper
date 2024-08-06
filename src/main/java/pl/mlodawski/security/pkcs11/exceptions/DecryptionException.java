package pl.mlodawski.security.pkcs11.exceptions;

/**
 * This class represents an exception that is thrown when an error occurs during decryption.
 */
public class DecryptionException extends RuntimeException {
    public DecryptionException(String message, Throwable cause) {
        super(message, cause);
    }
}