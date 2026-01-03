package pl.mlodawski.security.pkcs11;

import lombok.extern.slf4j.Slf4j;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import pl.mlodawski.security.pkcs11.exceptions.DecryptionException;
import pl.mlodawski.security.pkcs11.exceptions.EncryptionException;
import pl.mlodawski.security.pkcs11.exceptions.InvalidInputException;
import pl.mlodawski.security.pkcs11.jna.Cryptoki;
import pl.mlodawski.security.pkcs11.jna.constants.MechanismType;
import pl.mlodawski.security.pkcs11.jna.constants.ReturnValue;
import pl.mlodawski.security.pkcs11.jna.structure.Mechanism;
import com.sun.jna.NativeLong;
import com.sun.jna.ptr.NativeLongByReference;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.security.cert.X509Certificate;

/**
 * The {@code PKCS11Crypto} class provides methods for encrypting and decrypting data using
 * a combination of AES and RSA algorithms. It leverages PKCS#11 for RSA decryption in hardware
 * security modules (HSMs).
 *
 * This class uses the following transformations:
 * - AES: "AES/CBC/PKCS5Padding"
 * - RSA: "RSA/ECB/PKCS1Padding"
 */
@Slf4j
public class PKCS11Crypto {

    private static final int AES_KEY_SIZE = 256;
    private static final String AES_TRANSFORMATION = "AES/CBC/PKCS5Padding";
    private static final String RSA_TRANSFORMATION = "RSA/ECB/PKCS1Padding";

    /**
     * Encrypts the given data using AES encryption and then encrypts the AES key with RSA.
     *
     * @param dataToEncrypt the data to be encrypted
     * @param certificate the X509 certificate containing the public key for RSA encryption
     * @return a byte array containing the encrypted AES key, IV, and the encrypted data
     * @throws EncryptionException if any error occurs during the encryption process
     */
    public byte[][] encryptData(byte[] dataToEncrypt, X509Certificate certificate) {
        validateEncryptInput(dataToEncrypt, certificate);

        try {
            KeyGenerator keyGen = KeyGenerator.getInstance("AES");
            keyGen.init(AES_KEY_SIZE);
            SecretKey aesKey = keyGen.generateKey();

            Cipher aesCipher = Cipher.getInstance(AES_TRANSFORMATION);
            aesCipher.init(Cipher.ENCRYPT_MODE, aesKey);
            byte[] iv = aesCipher.getIV();

            byte[] encryptedData = aesCipher.doFinal(dataToEncrypt);

            Cipher rsaCipher = Cipher.getInstance(RSA_TRANSFORMATION, new BouncyCastleProvider());
            rsaCipher.init(Cipher.ENCRYPT_MODE, certificate.getPublicKey());
            byte[] encryptedKey = rsaCipher.doFinal(aesKey.getEncoded());

            return new byte[][]{encryptedKey, iv, encryptedData};
        } catch (Exception e) {
            log.error("Encryption failed", e);
            throw new EncryptionException("Encryption failed", e);
        }
    }

    /**
     * Decrypts the provided encrypted package using the specified PKCS#11 session and private key.
     *
     * @param pkcs11 the PKCS#11 instance to use for decryption.
     * @param session the active PKCS#11 session.
     * @param privateKeyHandle the handle of the private key to use for decryption.
     * @param encryptedPackage a 2D array containing the encrypted components: the encrypted AES key, the IV, and the encrypted data.
     * @return the decrypted data as a byte array.
     * @throws DecryptionException if the decryption process fails.
     */
    public byte[] decryptData(Cryptoki pkcs11, NativeLong session, NativeLong privateKeyHandle, byte[][] encryptedPackage) {
        validateDecryptInput(pkcs11, session, privateKeyHandle, encryptedPackage);

        byte[] encryptedKey = encryptedPackage[0];
        byte[] iv = encryptedPackage[1];
        byte[] encryptedData = encryptedPackage[2];

        try {
            Mechanism mechanism = new Mechanism(MechanismType.RSA_PKCS);
            NativeLong rv = pkcs11.C_DecryptInit(session, mechanism, privateKeyHandle);
            checkResult(rv, "Failed to initialize decryption");

            byte[] aesKeyBytes = decrypt(pkcs11, session, encryptedKey);
            SecretKey aesKey = new SecretKeySpec(aesKeyBytes, "AES");

            Cipher aesCipher = Cipher.getInstance(AES_TRANSFORMATION);
            aesCipher.init(Cipher.DECRYPT_MODE, aesKey, new javax.crypto.spec.IvParameterSpec(iv));
            return aesCipher.doFinal(encryptedData);
        } catch (Exception e) {
            log.error("Decryption failed", e);
            throw new DecryptionException("Decryption failed", e);
        }
    }

    /**
     * Decrypts the provided encrypted data using the given PKCS#11 session.
     *
     * @param pkcs11 the PKCS#11 interface to perform cryptographic operations
     * @param session the session handle used for decryption operations
     * @param encryptedData the data to be decrypted
     * @return the decrypted data as a byte array
     * @throws DecryptionException if the decryption process fails
     */
    private byte[] decrypt(Cryptoki pkcs11, NativeLong session, byte[] encryptedData) {
        try {
            NativeLongByReference decryptedDataLen = new NativeLongByReference();
            NativeLong result = pkcs11.C_Decrypt(session, encryptedData, new NativeLong(encryptedData.length), null, decryptedDataLen);
            checkResult(result, "Decryption failed with error code");

            byte[] decryptedData = new byte[decryptedDataLen.getValue().intValue()];
            result = pkcs11.C_Decrypt(session, encryptedData, new NativeLong(encryptedData.length), decryptedData, decryptedDataLen);
            checkResult(result, "Decryption failed with error code");

            return decryptedData;
        } catch (Exception e) {
            log.error("Decryption failed", e);
            throw new DecryptionException("Decryption failed", e);
        }
    }

    /**
     * Helper method to check the result from PKCS#11 calls.
     *
     * @param result the result code returned from the PKCS#11 call.
     * @param errorMessage the error message to include in the exception if the result is not CKR_OK.
     * @throws DecryptionException if the result is not CKR_OK.
     */
    private void checkResult(NativeLong result, String errorMessage) {
        if (!ReturnValue.isSuccess(result)) {
            throw new DecryptionException(errorMessage + ": " + result, null);
        }
    }

    /**
     * Validates the input parameters for the encryption process.
     *
     * @param dataToEncrypt the data to be encrypted, which must not be null or empty
     * @param certificate the X509Certificate to be used for encryption, which must not be null and must contain a public key
     * @throws InvalidInputException if any of the input parameters are invalid
     */
    private void validateEncryptInput(byte[] dataToEncrypt, X509Certificate certificate) {
        if (dataToEncrypt == null || dataToEncrypt.length == 0) {
            throw new InvalidInputException("dataToEncrypt cannot be null or empty");
        }
        if (certificate == null || certificate.getPublicKey() == null) {
            throw new InvalidInputException("certificate or its public key cannot be null");
        }
    }

    /**
     * Validates the input for decryption.
     *
     * @param pkcs11 the instance of Pkcs11, cannot be null
     * @param session the session handle, cannot be null
     * @param privateKeyHandle the handle of the private key, cannot be null
     * @param encryptedPackage the encrypted data package, must be an array of three non-null byte arrays
     * @throws InvalidInputException if any of the input parameters are invalid
     */
    private void validateDecryptInput(Cryptoki pkcs11, NativeLong session, NativeLong privateKeyHandle, byte[][] encryptedPackage) {
        if (pkcs11 == null) {
            throw new InvalidInputException("pkcs11 instance cannot be null");
        }
        if (session == null || privateKeyHandle == null) {
            throw new InvalidInputException("session and privateKeyHandle cannot be null");
        }
        if (encryptedPackage == null || encryptedPackage.length != 3) {
            throw new InvalidInputException("encryptedPackage format is invalid");
        }
        if (encryptedPackage[0] == null || encryptedPackage[1] == null || encryptedPackage[2] == null) {
            throw new InvalidInputException("encryptedPackage elements cannot be null");
        }
    }
}