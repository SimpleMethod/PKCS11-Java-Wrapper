package pl.mlodawski.security.pkcs11.exceptions;

/**
 * Exception thrown when there is an error creating a certificate.
 */
public class CertificateCreationException extends RuntimeException {
    public CertificateCreationException(String message, Throwable cause) {
        super(message, cause);
    }
}
