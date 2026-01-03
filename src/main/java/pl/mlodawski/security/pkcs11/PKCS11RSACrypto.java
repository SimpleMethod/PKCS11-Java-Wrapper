package pl.mlodawski.security.pkcs11;

import com.sun.jna.NativeLong;
import com.sun.jna.ptr.NativeLongByReference;
import lombok.extern.slf4j.Slf4j;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import pl.mlodawski.security.pkcs11.exceptions.CryptoInitializationException;
import pl.mlodawski.security.pkcs11.exceptions.DecryptionException;
import pl.mlodawski.security.pkcs11.exceptions.EncryptionException;
import pl.mlodawski.security.pkcs11.exceptions.InvalidInputException;
import pl.mlodawski.security.pkcs11.jna.Cryptoki;
import pl.mlodawski.security.pkcs11.jna.constants.MechanismType;
import pl.mlodawski.security.pkcs11.jna.constants.ReturnValue;
import pl.mlodawski.security.pkcs11.jna.structure.Mechanism;

import javax.crypto.Cipher;
import java.security.cert.X509Certificate;

/**
 * PKCS11RSACrypto is a class that provides encryption and decryption methods
 * using RSA algorithm and PKCS#11 standard.
 */
@Slf4j
public class PKCS11RSACrypto {

    /**
     * Initializes the cryptology process with the specified PKCS11 object, session, and private key handle.
     *
     * @param pkcs11 the PKCS11 object used for decryption
     * @param session the session used for decryption
     * @param privateKeyHandle the handle to the private key used for decryption
     * @throws IllegalArgumentException if any of the parameters is null
     * @throws RuntimeException if the decryption initialization fails
     */
    private void initCrypto(Cryptoki pkcs11, NativeLong session, NativeLong privateKeyHandle) {
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
            Mechanism mechanism = new Mechanism(MechanismType.RSA_PKCS);
            log.debug("Created mechanism: type=0x{}, paramLen={}",
                    Long.toHexString(mechanism.mechanism.longValue()),
                    mechanism.ulParameterLen.longValue());
            NativeLong rv = pkcs11.C_DecryptInit(session, mechanism, privateKeyHandle);
            if (rv.longValue() != 0) {
                throw new CryptoInitializationException(
                        "C_DecryptInit failed with error code: 0x" + Long.toHexString(rv.longValue()), null);
            }
            log.debug("Initialized decryption");
        } catch (CryptoInitializationException e) {
            throw e;
        } catch (Exception e) {
            log.error("Crypto initialization failed", e);
            throw new CryptoInitializationException("Crypto initialization failed", e);
        }
    }

    /**
     * Encrypts the given data using RSA algorithm with the provided X509 certificate.
     * Uses PKCS#1 v1.5 padding.
     *
     * @param dataToEncrypt   the data to be encrypted
     * @param certificate     the X509 certificate used for encryption
     * @return the encrypted data
     * @throws IllegalArgumentException if dataToEncrypt is null or empty, or if certificate is null
     * @throws RuntimeException if encryption fails
     */
    public byte[] encryptData(byte[] dataToEncrypt, X509Certificate certificate) {
        if (dataToEncrypt == null || dataToEncrypt.length == 0) {
            throw new IllegalArgumentException("dataToEncrypt cannot be null or empty");
        }
        if (certificate == null) {
            throw new IllegalArgumentException("certificate cannot be null");
        }

        try {
            Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding", new BouncyCastleProvider());
            cipher.init(Cipher.ENCRYPT_MODE, certificate.getPublicKey());
            return cipher.doFinal(dataToEncrypt);
        } catch (Exception e) {
            log.error("Encryption failed", e);
            throw new EncryptionException("Encryption failed", e);
        }
    }

    /**
     * Decrypts the given encrypted data using the specified private key.
     * Uses PKCS#1 v1.5 padding.
     *
     * @param pkcs11 the Pkcs11 instance used for decryption
     * @param session the native long value representing the session
     * @param privateKeyHandle the native long value representing the private key handle
     * @param encryptedData the byte array of encrypted data to be decrypted
     * @return the decrypted data as a byte array
     * @throws IllegalArgumentException if any of the input parameters are null or invalid
     * @throws RuntimeException if decryption fails
     */
    public byte[] decryptData(Cryptoki pkcs11, NativeLong session, NativeLong privateKeyHandle, byte[] encryptedData) {
        if (pkcs11 == null) {
            throw new IllegalArgumentException("pkcs11 cannot be null");
        }
        if (session == null) {
            throw new IllegalArgumentException("session cannot be null");
        }
        if (privateKeyHandle == null) {
            throw new IllegalArgumentException("privateKeyHandle cannot be null");
        }
        if (encryptedData == null || encryptedData.length == 0) {
            throw new InvalidInputException("encryptedData cannot be null or empty");
        }

        try {
            initCrypto(pkcs11, session, privateKeyHandle);
            return decrypt(pkcs11, session, encryptedData);
        } catch (CryptoInitializationException e) {
            log.error("Crypto initialization failed", e);
            throw e;
        } catch (Exception e) {
            log.error("Decryption failed", e);
            throw new DecryptionException("Decryption failed", e);
        }
    }

    /**
     * Decrypts the given encrypted data using PKCS11.
     *
     * @param pkcs11         the PKCS11 object used for encryption
     * @param session        the session ID
     * @param encryptedData  the data to decrypt
     * @return the decrypted data
     * @throws IllegalArgumentException if pkcs11, session, or encryptedData is null/empty
     * @throws RuntimeException if decryption fails
     */
    public byte[] decrypt(Cryptoki pkcs11, NativeLong session, byte[] encryptedData) {
        if (pkcs11 == null) {
            throw new IllegalArgumentException("pkcs11 cannot be null");
        }
        if (session == null) {
            throw new IllegalArgumentException("session cannot be null");
        }
        if (encryptedData == null || encryptedData.length == 0) {
            throw new IllegalArgumentException("encryptedData cannot be null or empty");
        }

        try {
            int bufferLen = encryptedData.length;
            byte[] decryptedData = new byte[bufferLen];
            NativeLongByReference decryptedDataLen = new NativeLongByReference(new NativeLong(bufferLen));

            NativeLong result = pkcs11.C_Decrypt(session, encryptedData, new NativeLong(encryptedData.length),
                    decryptedData, decryptedDataLen);
            if (!ReturnValue.isSuccess(result)) {
                throw new DecryptionException("Decryption failed with error code: 0x" + Long.toHexString(result.longValue()), null);
            }

            int actualLen = decryptedDataLen.getValue().intValue();
            if (actualLen < bufferLen) {
                byte[] trimmedData = new byte[actualLen];
                System.arraycopy(decryptedData, 0, trimmedData, 0, actualLen);
                return trimmedData;
            }
            return decryptedData;
        } catch (DecryptionException e) {
            throw e;
        } catch (Exception e) {
            log.error("Decryption failed", e);
            throw new DecryptionException("Decryption failed", e);
        }
    }

}