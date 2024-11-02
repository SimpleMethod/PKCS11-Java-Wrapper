package pl.mlodawski.security.pkcs11;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.Test;
import pl.mlodawski.security.pkcs11.exceptions.EncryptionException;
import pl.mlodawski.security.pkcs11.exceptions.InvalidInputException;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PublicKey;
import java.security.cert.X509Certificate;

import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

public class PKCS11CryptoTest {
    private static final String ENCRYPTION_FAILED_MESSAGE = "Encryption failed";



    @Test
    public void encryptData_InvalidInput_ThrowsException() {
        PKCS11Crypto pkcs11Crypto = new PKCS11Crypto();

        assertThrows(
                InvalidInputException.class,
                () -> pkcs11Crypto.encryptData(null, mock(X509Certificate.class))
        );

        X509Certificate certificate = mock(X509Certificate.class);
        when(certificate.getPublicKey()).thenReturn(null);

        assertThrows(
                InvalidInputException.class,
                () -> pkcs11Crypto.encryptData(new byte[1], certificate)
        );
    }

    @Test
    public void encryptData_EncryptionFails_ThrowsException() throws Exception {
        PKCS11Crypto pkcs11Crypto = new PKCS11Crypto();

        X509Certificate certificate = mock(X509Certificate.class);
        PublicKey publicKey = mock(PublicKey.class);

        when(certificate.getPublicKey()).thenReturn(publicKey);

        KeyGenerator keyGen = mock(KeyGenerator.class);
        SecretKey secretKey = mock(SecretKey.class);

        when(keyGen.generateKey()).thenReturn(secretKey);
        when(keyGen.generateKey()).thenThrow(new RuntimeException(ENCRYPTION_FAILED_MESSAGE));

        assertThrows(
                EncryptionException.class,
                () -> pkcs11Crypto.encryptData(new byte[1], certificate),
                ENCRYPTION_FAILED_MESSAGE
        );
    }

    @Test
    public void encryptData_ValidInput_Success() throws Exception {
        PKCS11Crypto pkcs11Crypto = new PKCS11Crypto();

        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
        keyGen.initialize(2048);
        KeyPair keyPair = keyGen.generateKeyPair();
        PublicKey publicKey = keyPair.getPublic();

        X509Certificate certificate = mock(X509Certificate.class);
        when(certificate.getPublicKey()).thenReturn(publicKey);

        byte[] dataToEncrypt = new byte[] { 0x01 };
        pkcs11Crypto.encryptData(dataToEncrypt, certificate);
    }
}