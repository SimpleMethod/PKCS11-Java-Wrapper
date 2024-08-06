package pl.mlodawski.security.pkcs11.exceptions;

/**
 * This class represents an exception that is thrown when there is an error retrieving a private key.
 * It extends the RuntimeException class.
 */
public class PrivateKeyRetrievalException extends RuntimeException {
    public PrivateKeyRetrievalException(String message, Throwable cause) {
        super(message, cause);
    }
}
