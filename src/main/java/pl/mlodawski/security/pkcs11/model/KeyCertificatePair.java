package pl.mlodawski.security.pkcs11.model;

import com.sun.jna.NativeLong;
import lombok.AllArgsConstructor;
import lombok.Data;

import java.security.cert.X509Certificate;

/**
 * Represents a pair of a key handle and an X.509 certificate with additional information.
 * This class holds a key handle which is a reference to a cryptographic key stored in an external device or software,
 * an X.509 certificate which is a digital document that uses a cryptographic key to bind a public key to an identity,
 * a CKA ID which is an identifier that represents the key in the cryptographic token,
 * and a CertificateInfo object which provides detailed information about the certificate.
 */
@Data
@AllArgsConstructor
public  class KeyCertificatePair {
    /**
     * The handle to the key.
     */
    public final NativeLong keyHandle;
    /**
     * The X.509 certificate.
     */
    public final X509Certificate certificate;
    /**
     * The CKA ID of the key.
     */
    public final String ckaId;
    /**
     * The certificate information.
     */
    public final CertificateInfo certificateInfo;
}
