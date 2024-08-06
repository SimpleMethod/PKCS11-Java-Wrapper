package pl.mlodawski.security.pkcs11.exceptions;

/**
 * This class represents an exception that is thrown when there is an error retrieving a key-certificate pair.
 * It is a subclass of the RuntimeException class.
 */
public class KeyCertificatePairRetrievalException extends RuntimeException {
    public KeyCertificatePairRetrievalException(String message, Throwable cause) {
        super(message, cause);
    }
}
