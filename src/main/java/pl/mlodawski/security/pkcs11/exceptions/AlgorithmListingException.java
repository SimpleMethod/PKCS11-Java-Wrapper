package pl.mlodawski.security.pkcs11.exceptions;

/**
 * Custom exception class used to indicate an error when listing algorithms.
 * This exception is intended to be thrown when there is an issue with listing algorithms.
 *
 *
 */
public class AlgorithmListingException extends RuntimeException {
    public AlgorithmListingException(String message, Throwable cause) {
        super(message, cause);
    }
}
