package pl.mlodawski.security.pkcs11;

import lombok.extern.slf4j.Slf4j;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import pl.mlodawski.security.pkcs11.exceptions.SignatureVerificationException;
import pl.mlodawski.security.pkcs11.exceptions.SigningException;
import pl.mlodawski.security.pkcs11.exceptions.SigningInitializationException;
import pl.mlodawski.security.pkcs11.jna.Cryptoki;
import pl.mlodawski.security.pkcs11.jna.constants.MechanismType;
import pl.mlodawski.security.pkcs11.jna.structure.Mechanism;
import com.sun.jna.NativeLong;
import com.sun.jna.ptr.NativeLongByReference;

import java.security.Signature;
import java.security.cert.X509Certificate;

@Slf4j
public class PKCS11Signer {

    /**
     * Supported RSA signing algorithms.
     */
    public enum SigningAlgorithm {
        /** SHA-256 with RSA PKCS#1 v1.5 padding */
        SHA256_RSA_PKCS(MechanismType.SHA256_RSA_PKCS, "SHA256withRSA"),
        /** SHA-384 with RSA PKCS#1 v1.5 padding */
        SHA384_RSA_PKCS(MechanismType.SHA384_RSA_PKCS, "SHA384withRSA"),
        /** SHA-512 with RSA PKCS#1 v1.5 padding */
        SHA512_RSA_PKCS(MechanismType.SHA512_RSA_PKCS, "SHA512withRSA"),
        /** SHA-1 with RSA PKCS#1 v1.5 padding */
        SHA1_RSA_PKCS(MechanismType.SHA1_RSA_PKCS, "SHA1withRSA"),
        /** SHA-224 with RSA PKCS#1 v1.5 padding */
        SHA224_RSA_PKCS(MechanismType.SHA224_RSA_PKCS, "SHA224withRSA");

        private final long mechanismType;
        private final String jcaAlgorithm;

        SigningAlgorithm(long mechanismType, String jcaAlgorithm) {
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
     * Initializes the signing mechanism with the given PKCS11 object, session handle, and private key handle.
     *
     * @param pkcs11 the PKCS11 object to use for signing
     * @param session the session handle to use for signing
     * @param privateKeyHandle the private key handle to use for signing
     *
     * @throws IllegalArgumentException if pkcs11, session, or privateKeyHandle is null
     * @throws RuntimeException if an error occurs while initializing the signing mechanism
     */
    private void initSigning(Cryptoki pkcs11, NativeLong session, NativeLong privateKeyHandle) {
        initSigning(pkcs11, session, privateKeyHandle, SigningAlgorithm.SHA256_RSA_PKCS);
    }

    /**
     * Initializes the signing mechanism with the specified algorithm.
     *
     * @param pkcs11 the PKCS11 object to use for signing
     * @param session the session handle to use for signing
     * @param privateKeyHandle the private key handle to use for signing
     * @param algorithm the signing algorithm to use
     *
     * @throws IllegalArgumentException if any parameter is null
     * @throws RuntimeException if an error occurs while initializing the signing mechanism
     */
    private void initSigning(Cryptoki pkcs11, NativeLong session, NativeLong privateKeyHandle, SigningAlgorithm algorithm) {
        if (pkcs11 == null) {
            throw new IllegalArgumentException("pkcs11 cannot be null");
        }
        if (session == null) {
            throw new IllegalArgumentException("session cannot be null");
        }
        if (privateKeyHandle == null) {
            throw new IllegalArgumentException("privateKeyHandle cannot be null");
        }
        if (algorithm == null) {
            throw new IllegalArgumentException("algorithm cannot be null");
        }

        try {
            Mechanism mechanism = new Mechanism(algorithm.getMechanismType());
            log.debug("Created mechanism: type=0x{}, paramLen={}",
                    Long.toHexString(mechanism.mechanism.longValue()),
                    mechanism.ulParameterLen.longValue());
            NativeLong rv = pkcs11.C_SignInit(session, mechanism, privateKeyHandle);
            if (rv.longValue() != 0) {
                throw new SigningInitializationException(
                        "C_SignInit failed with error code: 0x" + Long.toHexString(rv.longValue()), null);
            }
            log.debug("Initialized signing with algorithm: {}", algorithm.name());
        } catch (SigningInitializationException e) {
            throw e;
        } catch (Exception e) {
            log.error("Error initializing signing with algorithm: {}", algorithm.name(), e);
            throw new SigningInitializationException("Error initializing signing", e);
        }
    }

    /**
     * Signs a given message using a PKCS11 provider and a specified private key.
     * Uses SHA256_RSA_PKCS algorithm by default.
     * Supports large files via multi-part signing.
     *
     * @param pkcs11             The PKCS11 provider.
     * @param session            The session handle.
     * @param privateKeyHandle   The handle of the private key.
     * @param message            The message to be signed.
     * @return The signature of the message.
     * @throws IllegalArgumentException  If any of the parameters is null.
     * @throws RuntimeException          If there is an error signing the message.
     */
    public byte[] signMessage(Cryptoki pkcs11, NativeLong session, NativeLong privateKeyHandle, byte[] message) {
        return signMessage(pkcs11, session, privateKeyHandle, message, SigningAlgorithm.SHA256_RSA_PKCS);
    }

    /**
     * Signs a given message using a PKCS11 provider with specified algorithm.
     *
     * @param pkcs11             The PKCS11 provider.
     * @param session            The session handle.
     * @param privateKeyHandle   The handle of the private key.
     * @param message            The message to be signed.
     * @param algorithm          The signing algorithm to use.
     * @return The signature of the message.
     * @throws IllegalArgumentException  If any of the parameters is null.
     * @throws RuntimeException          If there is an error signing the message.
     */
    public byte[] signMessage(Cryptoki pkcs11, NativeLong session, NativeLong privateKeyHandle,
                              byte[] message, SigningAlgorithm algorithm) {
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

        try {
            initSigning(pkcs11, session, privateKeyHandle, algorithm);
            return sign(pkcs11, session, message, privateKeyHandle, algorithm);
        } catch (Exception e) {
            log.error("Error signing message with algorithm: {}", algorithm.name(), e);
            throw new SigningException("Error signing message", e);
        }
    }

    /**
     * Verifies the digital signature of a given message using a RSA public key certificate.
     * Uses SHA256_RSA_PKCS algorithm by default.
     *
     * @param message the message to be verified (cannot be null)
     * @param signature the signature to be verified (cannot be null)
     * @param certificate the X.509 certificate containing the public key used for verification (cannot be null)
     *
     * @return true if the signature is valid, false otherwise
     *
     * @throws IllegalArgumentException if any of the input parameters is null
     * @throws RuntimeException if an error occurs during the signature verification process
     */
    public boolean verifySignature(byte[] message, byte[] signature, X509Certificate certificate) {
        return verifySignature(message, signature, certificate, SigningAlgorithm.SHA256_RSA_PKCS);
    }

    /**
     * Verifies the digital signature of a given message using specified algorithm.
     *
     * @param message the message to be verified (cannot be null)
     * @param signature the signature to be verified (cannot be null)
     * @param certificate the X.509 certificate containing the public key used for verification (cannot be null)
     * @param algorithm the signing algorithm that was used to create the signature
     *
     * @return true if the signature is valid, false otherwise
     *
     * @throws IllegalArgumentException if any of the input parameters is null
     * @throws RuntimeException if an error occurs during the signature verification process
     */
    public boolean verifySignature(byte[] message, byte[] signature, X509Certificate certificate,
                                   SigningAlgorithm algorithm) {
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
            return sig.verify(signature);
        } catch (Exception e) {
            log.error("Error verifying signature with algorithm: {}", algorithm.name(), e);
            throw new SignatureVerificationException("Error verifying signature", e);
        }
    }



    /**
     * Sign a message using PKCS11.
     * For large data (> 16KB), uses multi-part signing with C_SignUpdate/C_SignFinal.
     *
     * @param pkcs11 The PKCS11 instance.
     * @param session The session handle.
     * @param message The message to be signed.
     * @param privateKeyHandle The private key handle (for re-initialization if needed).
     * @param algorithm The signing algorithm (for re-initialization if needed).
     * @return The signature of the message.
     * @throws IllegalArgumentException if any of the parameters is null.
     * @throws RuntimeException if an error occurs while signing the message.
     */
    private byte[] sign(Cryptoki pkcs11, NativeLong session, byte[] message,
                        NativeLong privateKeyHandle, SigningAlgorithm algorithm) {
        if (pkcs11 == null) {
            throw new IllegalArgumentException("pkcs11 cannot be null");
        }
        if (session == null) {
            throw new IllegalArgumentException("session cannot be null");
        }
        if (message == null) {
            throw new IllegalArgumentException("message cannot be null");
        }

        try {
            if (message.length > 16 * 1024) {
                return signMultiPart(pkcs11, session, message);
            }

            int maxSignatureLen = 512;
            byte[] signature = new byte[maxSignatureLen];
            NativeLongByReference signatureLen = new NativeLongByReference(new NativeLong(maxSignatureLen));

            NativeLong rv = pkcs11.C_Sign(session, message, new NativeLong(message.length), signature, signatureLen);
            if (rv.longValue() != 0) {
                if (rv.longValue() == 0x101) {
                    log.debug("Single-part signing failed with DATA_LEN_RANGE, trying multi-part");
                    initSigning(pkcs11, session, privateKeyHandle, algorithm);
                    return signMultiPart(pkcs11, session, message);
                }
                throw new SigningException("C_Sign failed with error code: 0x" + Long.toHexString(rv.longValue()), null);
            }

            int actualLen = signatureLen.getValue().intValue();
            if (actualLen < maxSignatureLen) {
                byte[] trimmedSignature = new byte[actualLen];
                System.arraycopy(signature, 0, trimmedSignature, 0, actualLen);
                return trimmedSignature;
            }
            return signature;
        } catch (SigningException e) {
            throw e;
        } catch (Exception e) {
            log.error("Error signing message", e);
            throw new SigningException("Error signing message", e);
        }
    }

    /**
     * Sign large data using multi-part operations (C_SignUpdate/C_SignFinal).
     */
    private byte[] signMultiPart(Cryptoki pkcs11, NativeLong session, byte[] message) {
        int chunkSize = 8 * 1024;
        int offset = 0;

        while (offset < message.length) {
            int remaining = message.length - offset;
            int currentChunkSize = Math.min(chunkSize, remaining);
            byte[] chunk = new byte[currentChunkSize];
            System.arraycopy(message, offset, chunk, 0, currentChunkSize);

            NativeLong rv = pkcs11.C_SignUpdate(session, chunk, new NativeLong(currentChunkSize));
            if (rv.longValue() != 0) {
                throw new SigningException("C_SignUpdate failed with error code: 0x" + Long.toHexString(rv.longValue()), null);
            }
            offset += currentChunkSize;
        }

        int maxSignatureLen = 512;
        byte[] signature = new byte[maxSignatureLen];
        NativeLongByReference signatureLen = new NativeLongByReference(new NativeLong(maxSignatureLen));

        NativeLong rv = pkcs11.C_SignFinal(session, signature, signatureLen);
        if (rv.longValue() != 0) {
            throw new SigningException("C_SignFinal failed with error code: 0x" + Long.toHexString(rv.longValue()), null);
        }

        int actualLen = signatureLen.getValue().intValue();
        if (actualLen < maxSignatureLen) {
            byte[] trimmedSignature = new byte[actualLen];
            System.arraycopy(signature, 0, trimmedSignature, 0, actualLen);
            return trimmedSignature;
        }
        return signature;
    }
}
