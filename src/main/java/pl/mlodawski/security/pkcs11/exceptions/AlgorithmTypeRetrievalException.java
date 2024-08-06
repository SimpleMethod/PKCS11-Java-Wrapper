package pl.mlodawski.security.pkcs11.exceptions;

/**
 * Exception indicating failure to retrieve the algorithm type.
 */
public class AlgorithmTypeRetrievalException extends RuntimeException {
    public AlgorithmTypeRetrievalException(String message, Throwable cause) {
        super(message, cause);
    }
}
