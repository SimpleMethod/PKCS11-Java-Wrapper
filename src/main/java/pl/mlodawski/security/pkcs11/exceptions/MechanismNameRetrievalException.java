package pl.mlodawski.security.pkcs11.exceptions;

/**
 * Custom exception class representing an error when retrieving a mechanism name.
 */
public class MechanismNameRetrievalException extends RuntimeException {
    public MechanismNameRetrievalException(String message, Throwable cause) {
        super(message, cause);
    }
}
