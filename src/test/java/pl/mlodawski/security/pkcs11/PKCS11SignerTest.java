package pl.mlodawski.security.pkcs11;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import pl.mlodawski.security.pkcs11.PKCS11Signer;
import pl.mlodawski.security.pkcs11.exceptions.SignatureVerificationException;
import pl.mlodawski.security.pkcs11.exceptions.SigningException;
import pl.mlodawski.security.pkcs11.exceptions.SigningInitializationException;
import ru.rutoken.pkcs11jna.CK_MECHANISM;
import ru.rutoken.pkcs11jna.Pkcs11;
import ru.rutoken.pkcs11jna.Pkcs11Constants;
import com.sun.jna.NativeLong;
import com.sun.jna.ptr.NativeLongByReference;

import java.security.PublicKey;
import java.security.Signature;
import java.security.cert.X509Certificate;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class PKCS11SignerTest {

    @Mock
    private Pkcs11 pkcs11Mock;

    @Mock
    private X509Certificate certificateMock;

    @Mock
    private PublicKey publicKeyMock;

    private PKCS11Signer pkcs11Signer;
    private NativeLong session;
    private NativeLong privateKeyHandle;
    private byte[] message;

    @BeforeEach
    void setUp() {
        pkcs11Signer = new PKCS11Signer();
        session = new NativeLong(1L);
        privateKeyHandle = new NativeLong(2L);
        message = "Test message".getBytes();
    }


    @Test
    void initSigning_nullPkcs11_shouldThrowIllegalArgumentException() {
        assertThrows(IllegalArgumentException.class, () -> pkcs11Signer.signMessage(null, session, privateKeyHandle, message));
    }

    @Test
    void initSigning_nullSession_shouldThrowIllegalArgumentException() {
        assertThrows(IllegalArgumentException.class, () -> pkcs11Signer.signMessage(pkcs11Mock, null, privateKeyHandle, message));
    }

    @Test
    void initSigning_nullPrivateKeyHandle_shouldThrowIllegalArgumentException() {
        assertThrows(IllegalArgumentException.class, () -> pkcs11Signer.signMessage(pkcs11Mock, session, null, message));
    }

    @Test
    void signMessage_nullMessage_shouldThrowIllegalArgumentException() {
        assertThrows(IllegalArgumentException.class, () -> pkcs11Signer.signMessage(pkcs11Mock, session, privateKeyHandle, null));
    }


    @Test
    void verifySignature_nullMessage_shouldThrowIllegalArgumentException() {
        byte[] signature = new byte[256];
        assertThrows(IllegalArgumentException.class, () -> pkcs11Signer.verifySignature(null, signature, certificateMock));
    }

    @Test
    void verifySignature_nullSignature_shouldThrowIllegalArgumentException() {
        assertThrows(IllegalArgumentException.class, () -> pkcs11Signer.verifySignature(message, null, certificateMock));
    }

    @Test
    void verifySignature_nullCertificate_shouldThrowIllegalArgumentException() {
        byte[] signature = new byte[256];
        assertThrows(IllegalArgumentException.class, () -> pkcs11Signer.verifySignature(message, signature, null));
    }

}
