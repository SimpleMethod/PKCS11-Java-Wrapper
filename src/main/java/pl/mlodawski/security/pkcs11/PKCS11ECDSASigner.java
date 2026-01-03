package pl.mlodawski.security.pkcs11;

import com.sun.jna.NativeLong;
import com.sun.jna.ptr.NativeLongByReference;
import lombok.extern.slf4j.Slf4j;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import pl.mlodawski.security.pkcs11.exceptions.SignatureVerificationException;
import pl.mlodawski.security.pkcs11.exceptions.SigningException;
import pl.mlodawski.security.pkcs11.exceptions.SigningInitializationException;
import pl.mlodawski.security.pkcs11.jna.Cryptoki;
import pl.mlodawski.security.pkcs11.jna.constants.MechanismType;
import pl.mlodawski.security.pkcs11.jna.structure.Mechanism;

import java.security.Signature;
import java.security.cert.X509Certificate;

/**
 * Provides ECDSA (Elliptic Curve Digital Signature Algorithm) signing
 * operations using PKCS#11 hardware tokens.
 */
@Slf4j
public class PKCS11ECDSASigner {

    /**
     * Supported ECDSA signing algorithms.
     */
    public enum ECDSAAlgorithm {
        /** Raw ECDSA - hash must be computed separately */
        ECDSA(MechanismType.ECDSA, "NONEwithECDSA"),
        /** ECDSA with SHA-1 hashing */
        ECDSA_SHA1(MechanismType.ECDSA_SHA1, "SHA1withECDSA"),
        /** ECDSA with SHA-224 hashing */
        ECDSA_SHA224(MechanismType.ECDSA_SHA224, "SHA224withECDSA"),
        /** ECDSA with SHA-256 hashing */
        ECDSA_SHA256(MechanismType.ECDSA_SHA256, "SHA256withECDSA"),
        /** ECDSA with SHA-384 hashing */
        ECDSA_SHA384(MechanismType.ECDSA_SHA384, "SHA384withECDSA"),
        /** ECDSA with SHA-512 hashing */
        ECDSA_SHA512(MechanismType.ECDSA_SHA512, "SHA512withECDSA");

        private final long mechanismType;
        private final String jcaAlgorithm;

        ECDSAAlgorithm(long mechanismType, String jcaAlgorithm) {
            this.mechanismType = mechanismType;
            this.jcaAlgorithm = jcaAlgorithm;
        }

        public long getMechanismType() {
            return mechanismType;
        }

        public String getJcaAlgorithm() {
            return jcaAlgorithm;
        }
    }

    /**
     * Signs a message using ECDSA with SHA-256 (default algorithm).
     *
     * @param pkcs11           the PKCS#11 interface
     * @param session          the session handle
     * @param privateKeyHandle the EC private key handle
     * @param message          the message to sign
     * @return the ECDSA signature
     */
    public byte[] signMessage(Cryptoki pkcs11, NativeLong session, NativeLong privateKeyHandle, byte[] message) {
        return signMessage(pkcs11, session, privateKeyHandle, message, ECDSAAlgorithm.ECDSA_SHA256);
    }

    /**
     * Signs a message using the specified ECDSA algorithm.
     *
     * @param pkcs11           the PKCS#11 interface
     * @param session          the session handle
     * @param privateKeyHandle the EC private key handle
     * @param message          the message to sign
     * @param algorithm        the ECDSA algorithm to use
     * @return the ECDSA signature
     */
    public byte[] signMessage(Cryptoki pkcs11, NativeLong session, NativeLong privateKeyHandle,
                              byte[] message, ECDSAAlgorithm algorithm) {
        validateParameters(pkcs11, session, privateKeyHandle, message, algorithm);

        try {
            initSigning(pkcs11, session, privateKeyHandle, algorithm);
            return sign(pkcs11, session, message);
        } catch (Exception e) {
            log.error("Error signing message with ECDSA algorithm: {}", algorithm.name(), e);
            throw new SigningException("Error signing message with ECDSA", e);
        }
    }

    /**
     * Signs a pre-computed hash using raw ECDSA.
     * Use this when you've already computed the hash of your data.
     *
     * @param pkcs11           the PKCS#11 interface
     * @param session          the session handle
     * @param privateKeyHandle the EC private key handle
     * @param hash             the pre-computed hash to sign
     * @return the ECDSA signature
     */
    public byte[] signHash(Cryptoki pkcs11, NativeLong session, NativeLong privateKeyHandle, byte[] hash) {
        return signMessage(pkcs11, session, privateKeyHandle, hash, ECDSAAlgorithm.ECDSA);
    }

    private void initSigning(Cryptoki pkcs11, NativeLong session, NativeLong privateKeyHandle,
                             ECDSAAlgorithm algorithm) {
        try {
            Mechanism mechanism = new Mechanism(algorithm.getMechanismType());
            pkcs11.C_SignInit(session, mechanism, privateKeyHandle);
            log.debug("Initialized ECDSA signing with algorithm: {}", algorithm.name());
        } catch (Exception e) {
            log.error("Error initializing ECDSA signing with algorithm: {}", algorithm.name(), e);
            throw new SigningInitializationException("Error initializing ECDSA signing", e);
        }
    }

    private byte[] sign(Cryptoki pkcs11, NativeLong session, byte[] data) {
        try {
            // Get signature length first
            NativeLongByReference signatureLen = new NativeLongByReference();
            pkcs11.C_Sign(session, data, new NativeLong(data.length), null, signatureLen);

            // Create signature
            byte[] signature = new byte[signatureLen.getValue().intValue()];
            pkcs11.C_Sign(session, data, new NativeLong(data.length), signature, signatureLen);

            log.debug("Created ECDSA signature of {} bytes", signature.length);
            return signature;
        } catch (Exception e) {
            log.error("Error during ECDSA signing", e);
            throw new SigningException("Error during ECDSA signing", e);
        }
    }

    /**
     * Verifies an ECDSA signature using SHA-256 (default algorithm).
     *
     * @param message     the original message
     * @param signature   the signature to verify
     * @param certificate the certificate containing the EC public key
     * @return true if the signature is valid
     */
    public boolean verifySignature(byte[] message, byte[] signature, X509Certificate certificate) {
        return verifySignature(message, signature, certificate, ECDSAAlgorithm.ECDSA_SHA256);
    }

    /**
     * Verifies an ECDSA signature using the specified algorithm.
     *
     * @param message     the original message
     * @param signature   the signature to verify
     * @param certificate the certificate containing the EC public key
     * @param algorithm   the ECDSA algorithm that was used for signing
     * @return true if the signature is valid
     */
    public boolean verifySignature(byte[] message, byte[] signature, X509Certificate certificate,
                                   ECDSAAlgorithm algorithm) {
        if (message == null) {
            throw new IllegalArgumentException("message cannot be null");
        }
        if (signature == null) {
            throw new IllegalArgumentException("signature cannot be null");
        }
        if (certificate == null) {
            throw new IllegalArgumentException("certificate cannot be null");
        }
        if (algorithm == null) {
            throw new IllegalArgumentException("algorithm cannot be null");
        }

        try {
            Signature sig = Signature.getInstance(algorithm.getJcaAlgorithm(), new BouncyCastleProvider());
            sig.initVerify(certificate.getPublicKey());
            sig.update(message);
            boolean valid = sig.verify(signature);
            log.debug("ECDSA signature verification result: {}", valid);
            return valid;
        } catch (Exception e) {
            log.error("Error verifying ECDSA signature with algorithm: {}", algorithm.name(), e);
            throw new SignatureVerificationException("Error verifying ECDSA signature", e);
        }
    }

    private void validateParameters(Cryptoki pkcs11, NativeLong session, NativeLong privateKeyHandle,
                                    byte[] message, ECDSAAlgorithm algorithm) {
        if (pkcs11 == null) {
            throw new IllegalArgumentException("pkcs11 cannot be null");
        }
        if (session == null) {
            throw new IllegalArgumentException("session cannot be null");
        }
        if (privateKeyHandle == null) {
            throw new IllegalArgumentException("privateKeyHandle cannot be null");
        }
        if (message == null) {
            throw new IllegalArgumentException("message cannot be null");
        }
        if (algorithm == null) {
            throw new IllegalArgumentException("algorithm cannot be null");
        }
    }
}
