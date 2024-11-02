package pl.mlodawski.security.pkcs11;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import pl.mlodawski.security.pkcs11.exceptions.CryptoInitializationException;
import pl.mlodawski.security.pkcs11.exceptions.DecryptionException;
import pl.mlodawski.security.pkcs11.exceptions.EncryptionException;
import pl.mlodawski.security.pkcs11.exceptions.InvalidInputException;
import ru.rutoken.pkcs11jna.Pkcs11;

import javax.crypto.Cipher;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.cert.X509Certificate;

import com.sun.jna.NativeLong;
import com.sun.jna.ptr.NativeLongByReference;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class PKCS11RSACryptoTest {

    @Mock
    private Pkcs11 pkcs11Mock;

    @Mock
    private X509Certificate certificateMock;

    private PKCS11RSACrypto pkcs11Crypto;
    private KeyPair keyPair;
    private NativeLong session;
    private NativeLong privateKeyHandle;

    @BeforeEach
    void setUp() throws Exception {
        pkcs11Crypto = new PKCS11RSACrypto();
        session = new NativeLong(1L);
        privateKeyHandle = new NativeLong(2L);

        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
        keyPairGenerator.initialize(2048);
        keyPair = keyPairGenerator.generateKeyPair();

    }

    @Test
    void encryptData_validInput_shouldEncryptSuccessfully() throws Exception {
        when(certificateMock.getPublicKey()).thenReturn(keyPair.getPublic());
        byte[] dataToEncrypt = "Hello, World!".getBytes();

        byte[] encryptedData = pkcs11Crypto.encryptData(dataToEncrypt, certificateMock);

        assertNotNull(encryptedData);
        assertNotEquals(dataToEncrypt, encryptedData);
    }

    @Test
    void encryptData_nullData_shouldThrowIllegalArgumentException() {
        assertThrows(IllegalArgumentException.class, () -> pkcs11Crypto.encryptData(null, certificateMock));
    }

    @Test
    void encryptData_emptyData_shouldThrowIllegalArgumentException() {
        assertThrows(IllegalArgumentException.class, () -> pkcs11Crypto.encryptData(new byte[0], certificateMock));
    }

    @Test
    void encryptData_nullCertificate_shouldThrowIllegalArgumentException() {
        assertThrows(IllegalArgumentException.class, () -> pkcs11Crypto.encryptData("Test".getBytes(), null));
    }

    @Test
    void encryptData_invalidCertificate_shouldThrowEncryptionException() {
        when(certificateMock.getPublicKey()).thenThrow(new RuntimeException("Invalid certificate"));
        assertThrows(EncryptionException.class, () -> pkcs11Crypto.encryptData("Test".getBytes(), certificateMock));
    }

    @Test
    void decryptData_validInput_shouldDecryptSuccessfully() throws Exception {
        byte[] originalData = "Hello, World!".getBytes();
        byte[] encryptedData = encryptWithRealKey(originalData);

        // Mock PKCS11 behavior
        when(pkcs11Mock.C_Decrypt(eq(session), any(), any(), isNull(), any())).thenAnswer(invocation -> {
            NativeLongByReference lengthRef = invocation.getArgument(4);
            lengthRef.setValue(new NativeLong(originalData.length));
            return new NativeLong(0);
        });

        when(pkcs11Mock.C_Decrypt(eq(session), any(), any(), any(byte[].class), any())).thenAnswer(invocation -> {
            byte[] outputBuffer = invocation.getArgument(3);
            System.arraycopy(originalData, 0, outputBuffer, 0, originalData.length);
            return new NativeLong(0);
        });

        byte[] decryptedData = pkcs11Crypto.decryptData(pkcs11Mock, session, privateKeyHandle, encryptedData);

        assertArrayEquals(originalData, decryptedData);
    }

    @Test
    void decryptData_nullPkcs11_shouldThrowIllegalArgumentException() {
        assertThrows(IllegalArgumentException.class, () -> pkcs11Crypto.decryptData(null, session, privateKeyHandle, new byte[]{1}));
    }

    @Test
    void decryptData_nullSession_shouldThrowIllegalArgumentException() {
        assertThrows(IllegalArgumentException.class, () -> pkcs11Crypto.decryptData(pkcs11Mock, null, privateKeyHandle, new byte[]{1}));
    }

    @Test
    void decryptData_nullPrivateKeyHandle_shouldThrowIllegalArgumentException() {
        assertThrows(IllegalArgumentException.class, () -> pkcs11Crypto.decryptData(pkcs11Mock, session, null, new byte[]{1}));
    }

    @Test
    void decryptData_nullEncryptedData_shouldThrowInvalidInputException() {
        assertThrows(InvalidInputException.class, () -> pkcs11Crypto.decryptData(pkcs11Mock, session, privateKeyHandle, null));
    }

    @Test
    void decryptData_emptyEncryptedData_shouldThrowInvalidInputException() {
        assertThrows(InvalidInputException.class, () -> pkcs11Crypto.decryptData(pkcs11Mock, session, privateKeyHandle, new byte[0]));
    }

    @Test
    void decryptData_initializationFailure_shouldThrowCryptoInitializationException() {
        doThrow(new RuntimeException("Initialization failed")).when(pkcs11Mock).C_DecryptInit(any(), any(), any());

        assertThrows(CryptoInitializationException.class, () ->
                pkcs11Crypto.decryptData(pkcs11Mock, session, privateKeyHandle, new byte[]{1}));
    }

    @Test
    void decryptData_decryptionFailure_shouldThrowDecryptionException() {
        when(pkcs11Mock.C_Decrypt(any(), any(), any(), any(), any())).thenReturn(new NativeLong(1));

        assertThrows(DecryptionException.class, () ->
                pkcs11Crypto.decrypt(pkcs11Mock, session, new byte[]{1}));
    }

    private byte[] encryptWithRealKey(byte[] data) throws Exception {
        Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        cipher.init(Cipher.ENCRYPT_MODE, keyPair.getPublic());
        return cipher.doFinal(data);
    }
}