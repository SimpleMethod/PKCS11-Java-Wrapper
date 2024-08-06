package pl.mlodawski.security.pkcs11.exceptions;

/**
 * Exception thrown when finalizing the PKCS#11 library fails.
 */
public class PKCS11FinalizationException extends RuntimeException {
    public PKCS11FinalizationException(String message, Throwable cause) {
        super(message, cause);
    }
}
