package pl.mlodawski.security.pkcs11;

import com.sun.jna.NativeLong;
import com.sun.jna.ptr.NativeLongByReference;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import pl.mlodawski.security.pkcs11.jna.Cryptoki;
import pl.mlodawski.security.pkcs11.jna.constants.ReturnValue;
import pl.mlodawski.security.pkcs11.jna.structure.Mechanism;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class PKCS11ECDSASignerTest {

    @Mock
    private Cryptoki pkcs11Mock;

    private NativeLong session;
    private NativeLong privateKeyHandle;
    private PKCS11ECDSASigner signer;

    @BeforeEach
    void setUp() {
        session = new NativeLong(1L);
        privateKeyHandle = new NativeLong(2L);
        signer = new PKCS11ECDSASigner();
    }

    @Test
    void signMessage_nullPkcs11_shouldThrowIllegalArgumentException() {
        assertThrows(IllegalArgumentException.class, () ->
                signer.signMessage(null, session, privateKeyHandle, "test".getBytes()));
    }

    @Test
    void signMessage_nullSession_shouldThrowIllegalArgumentException() {
        assertThrows(IllegalArgumentException.class, () ->
                signer.signMessage(pkcs11Mock, null, privateKeyHandle, "test".getBytes()));
    }

    @Test
    void signMessage_nullPrivateKeyHandle_shouldThrowIllegalArgumentException() {
        assertThrows(IllegalArgumentException.class, () ->
                signer.signMessage(pkcs11Mock, session, null, "test".getBytes()));
    }

    @Test
    void signMessage_nullMessage_shouldThrowIllegalArgumentException() {
        assertThrows(IllegalArgumentException.class, () ->
                signer.signMessage(pkcs11Mock, session, privateKeyHandle, null));
    }

    @Test
    void signMessage_nullAlgorithm_shouldThrowIllegalArgumentException() {
        assertThrows(IllegalArgumentException.class, () ->
                signer.signMessage(pkcs11Mock, session, privateKeyHandle, "test".getBytes(), null));
    }

    @Test
    void signMessage_validInput_shouldReturnSignature() {
        byte[] message = "test message".getBytes();
        byte[] expectedSignature = new byte[64]; // Typical ECDSA signature size

        when(pkcs11Mock.C_SignInit(any(NativeLong.class), any(Mechanism.class), any(NativeLong.class)))
                .thenReturn(new NativeLong(ReturnValue.OK));

        when(pkcs11Mock.C_Sign(any(NativeLong.class), any(byte[].class), any(NativeLong.class),
                isNull(), any(NativeLongByReference.class)))
                .thenAnswer(invocation -> {
                    NativeLongByReference lenRef = invocation.getArgument(4);
                    lenRef.setValue(new NativeLong(64));
                    return new NativeLong(ReturnValue.OK);
                });

        when(pkcs11Mock.C_Sign(any(NativeLong.class), any(byte[].class), any(NativeLong.class),
                any(byte[].class), any(NativeLongByReference.class)))
                .thenReturn(new NativeLong(ReturnValue.OK));

        byte[] signature = signer.signMessage(pkcs11Mock, session, privateKeyHandle, message);

        assertNotNull(signature);
        assertEquals(64, signature.length);
        verify(pkcs11Mock).C_SignInit(eq(session), any(Mechanism.class), eq(privateKeyHandle));
    }

    @Test
    void signMessage_withSHA384_shouldUseCorrectMechanism() {
        byte[] message = "test".getBytes();

        when(pkcs11Mock.C_SignInit(any(NativeLong.class), any(Mechanism.class), any(NativeLong.class)))
                .thenReturn(new NativeLong(ReturnValue.OK));

        when(pkcs11Mock.C_Sign(any(NativeLong.class), any(byte[].class), any(NativeLong.class),
                isNull(), any(NativeLongByReference.class)))
                .thenAnswer(invocation -> {
                    NativeLongByReference lenRef = invocation.getArgument(4);
                    lenRef.setValue(new NativeLong(96));
                    return new NativeLong(ReturnValue.OK);
                });

        when(pkcs11Mock.C_Sign(any(NativeLong.class), any(byte[].class), any(NativeLong.class),
                any(byte[].class), any(NativeLongByReference.class)))
                .thenReturn(new NativeLong(ReturnValue.OK));

        byte[] signature = signer.signMessage(pkcs11Mock, session, privateKeyHandle, message,
                PKCS11ECDSASigner.ECDSAAlgorithm.ECDSA_SHA384);

        assertNotNull(signature);
        verify(pkcs11Mock).C_SignInit(eq(session), any(Mechanism.class), eq(privateKeyHandle));
    }

    @Test
    void signHash_shouldUseRawECDSA() {
        byte[] hash = new byte[32]; // SHA-256 hash

        when(pkcs11Mock.C_SignInit(any(NativeLong.class), any(Mechanism.class), any(NativeLong.class)))
                .thenReturn(new NativeLong(ReturnValue.OK));

        when(pkcs11Mock.C_Sign(any(NativeLong.class), any(byte[].class), any(NativeLong.class),
                isNull(), any(NativeLongByReference.class)))
                .thenAnswer(invocation -> {
                    NativeLongByReference lenRef = invocation.getArgument(4);
                    lenRef.setValue(new NativeLong(64));
                    return new NativeLong(ReturnValue.OK);
                });

        when(pkcs11Mock.C_Sign(any(NativeLong.class), any(byte[].class), any(NativeLong.class),
                any(byte[].class), any(NativeLongByReference.class)))
                .thenReturn(new NativeLong(ReturnValue.OK));

        byte[] signature = signer.signHash(pkcs11Mock, session, privateKeyHandle, hash);

        assertNotNull(signature);
        verify(pkcs11Mock).C_SignInit(eq(session), any(Mechanism.class), eq(privateKeyHandle));
    }

    @Test
    void verifySignature_nullMessage_shouldThrowIllegalArgumentException() {
        assertThrows(IllegalArgumentException.class, () ->
                signer.verifySignature(null, new byte[64], null));
    }

    @Test
    void verifySignature_nullSignature_shouldThrowIllegalArgumentException() {
        assertThrows(IllegalArgumentException.class, () ->
                signer.verifySignature("test".getBytes(), null, null));
    }

    @Test
    void verifySignature_nullCertificate_shouldThrowIllegalArgumentException() {
        assertThrows(IllegalArgumentException.class, () ->
                signer.verifySignature("test".getBytes(), new byte[64], null));
    }
}
