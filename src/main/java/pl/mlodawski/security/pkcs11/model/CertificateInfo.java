package pl.mlodawski.security.pkcs11.model;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.math.BigInteger;
import java.security.PublicKey;
import java.util.Collection;
import java.util.Date;
import java.util.List;

/**
 * Represents information about a certificate.
 * The fields in this class provide details and properties of a certificate.
 */
@Data
@AllArgsConstructor
@NoArgsConstructor
public class CertificateInfo {
    /**
     * The subject of the certificate.
     */
    private String subject;
    /**
     * The issuer of the certificate.
     */
    private String issuer;
    /**
     * The serial number of the certificate.
     */
    private BigInteger serialNumber;
    /**
     * The signature of the certificate.
     */
    private byte[] signature;
    /**
     * The not before date of the certificate.
     */
    private Date notBefore;
    /**
     * The not after date of the certificate.
     */
    private Date notAfter;
    /**
     * The signature algorithm of the certificate.
     */
    private String signatureAlgorithm;
    /**
     * The signature algorithm OID of the certificate.
     */
    private String signatureAlgorithmOID;
    /**
     * The public key algorithm of the certificate.
     */
    private byte[] tbsCertificate;
    /**
     * The version of the certificate.
     */
    private int version;
    /**
     * The public key of the certificate.
     */
    private PublicKey publicKey;
    /**
     * The subject key identifier of the certificate.
     */
    private boolean[] issuerUniqueID;
    /**
     * The subject unique identifier of the certificate.
     */
    private boolean[] subjectUniqueID;
    /**
     * The key usage of the certificate.
     */
    private boolean[] keyUsage;
    /**
     * The extended key usage of the certificate.
     */
    private List<String> extendedKeyUsage;
    /**
     * The basic constraints of the certificate.
     */
    private int basicConstraints;
    /**
     * The subject alternative names of the certificate.
     */
    private Collection<List<?>> subjectAlternativeNames;
    /**
     * The issuer alternative names of the certificate.
     */
    private Collection<List<?>> issuerAlternativeNames;
    /**
     * The encoded form of the certificate.
     */
    private byte[] encoded;
}