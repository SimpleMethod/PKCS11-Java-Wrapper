package pl.mlodawski.security.pkcs11;

import lombok.extern.slf4j.Slf4j;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import pl.mlodawski.security.pkcs11.exceptions.SignatureVerificationException;
import pl.mlodawski.security.pkcs11.exceptions.SigningException;
import pl.mlodawski.security.pkcs11.exceptions.SigningInitializationException;
import ru.rutoken.pkcs11jna.CK_MECHANISM;
import ru.rutoken.pkcs11jna.Pkcs11;
import ru.rutoken.pkcs11jna.Pkcs11Constants;
import com.sun.jna.NativeLong;
import com.sun.jna.ptr.NativeLongByReference;

import java.security.Signature;
import java.security.cert.X509Certificate;

@Slf4j
public class PKCS11Signer {

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
    private void initSigning(Pkcs11 pkcs11, NativeLong session, NativeLong privateKeyHandle) {
        if (pkcs11 == null) {
            throw new IllegalArgumentException("pkcs11 cannot be null");
        }
        if (session == null) {
            throw new IllegalArgumentException("session cannot be null");
        }
        if (privateKeyHandle == null) {
            throw new IllegalArgumentException("privateKeyHandle cannot be null");
        }

        try {
            CK_MECHANISM mechanism = new CK_MECHANISM();
            mechanism.mechanism = new NativeLong(Pkcs11Constants.CKM_SHA256_RSA_PKCS);
            pkcs11.C_SignInit(session, mechanism, privateKeyHandle);
        } catch (Exception e) {
            log.error("Error initializing signing", e);
            throw new SigningInitializationException("Error initializing signing", e);
        }
    }

    /**
     * Signs a given message using a PKCS11 provider and a specified private key.
     *
     * @param pkcs11             The PKCS11 provider.
     * @param session            The session handle.
     * @param privateKeyHandle   The handle of the private key.
     * @param message            The message to be signed.
     * @return The signature of the message.
     * @throws IllegalArgumentException  If any of the parameters is null.
     * @throws RuntimeException          If there is an error signing the message.
     */
    public byte[] signMessage(Pkcs11 pkcs11, NativeLong session, NativeLong privateKeyHandle, byte[] message) {
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

        try {
            initSigning(pkcs11, session, privateKeyHandle);
            return sign(pkcs11, session, message);
        } catch (Exception e) {
            log.error("Error signing message", e);
            throw new SigningException("Error signing message", e);
        }
    }

    /**
     * Verifies the digital signature of a given message using a RSA public key certificate.
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
        if (message == null) {
            throw new IllegalArgumentException("message cannot be null");
        }
        if (signature == null) {
            throw new IllegalArgumentException("signature cannot be null");
        }
        if (certificate == null) {
            throw new IllegalArgumentException("certificate cannot be null");
        }

        try {
            Signature sig = Signature.getInstance("SHA256withRSA", new BouncyCastleProvider());
            sig.initVerify(certificate.getPublicKey());
            sig.update(message);
            return sig.verify(signature);
        } catch (Exception e) {
            log.error("Error verifying signature", e);
            throw new SignatureVerificationException("Error verifying signature", e);
        }
    }



    /**
     * Sign a message using PKCS11.
     *
     * @param pkcs11 The PKCS11 instance.
     * @param session The session handle.
     * @param message The message to be signed.
     * @return The signature of the message.
     * @throws IllegalArgumentException if any of the parameters is null.
     * @throws RuntimeException if an error occurs while signing the message.
     */
    private byte[] sign(Pkcs11 pkcs11, NativeLong session, byte[] message) {
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
            NativeLongByReference signatureLen = new NativeLongByReference();
            pkcs11.C_Sign(session, message, new NativeLong(message.length), null, signatureLen);

            byte[] signature = new byte[signatureLen.getValue().intValue()];
            pkcs11.C_Sign(session, message, new NativeLong(message.length), signature, signatureLen);

            return signature;
        } catch (Exception e) {
            log.error("Error signing message", e);
            throw new SigningException("Error signing message", e);
        }
    }
}
