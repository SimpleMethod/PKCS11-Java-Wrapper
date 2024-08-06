package pl.mlodawski.security.pkcs11.exceptions;

/**
 * This class represents an exception that occurs when retrieving a list of mechanisms.
 * It extends the RuntimeException class, making it an unchecked exception.
 *
 */
public class MechanismListRetrievalException extends RuntimeException {
    public MechanismListRetrievalException(String message, Throwable cause) {
        super(message, cause);
    }
}
