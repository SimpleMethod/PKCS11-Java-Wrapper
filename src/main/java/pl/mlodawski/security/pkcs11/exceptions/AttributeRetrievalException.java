package pl.mlodawski.security.pkcs11.exceptions;

/**
 * This class represents an exception that is thrown when an attribute retrieval fails.
 * It extends the RuntimeException class.
 *
 */
public class AttributeRetrievalException extends RuntimeException {
    public AttributeRetrievalException(String message, Throwable cause) {
        super(message, cause);
    }
}
