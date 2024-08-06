package pl.mlodawski.security.pkcs11.exceptions;

/**
 * CertificateRetrievalException is an exception that is thrown when there
 * is an error retrieving a certificate.
 *
 * This exception extends the RuntimeException class, therefore it is an
 * unchecked exception and does not require explicit declaration in the
 * method signature or try-catch blocks.
 */
public class CertificateRetrievalException extends RuntimeException {
    public CertificateRetrievalException(String message, Throwable cause) {
        super(message, cause);
    }
}
