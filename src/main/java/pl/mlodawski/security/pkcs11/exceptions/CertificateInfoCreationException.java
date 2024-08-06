package pl.mlodawski.security.pkcs11.exceptions;

/**
 * Exception thrown when there is an error creating a certificate info.
 * This exception extends the RuntimeException class.
 */
public class CertificateInfoCreationException extends RuntimeException {
    public CertificateInfoCreationException(String message, Throwable cause) {
        super(message, cause);
    }
}
