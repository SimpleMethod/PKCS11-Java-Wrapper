package pl.mlodawski.security.pkcs11;

import com.sun.jna.NativeLong;
import com.sun.jna.ptr.NativeLongByReference;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import pl.mlodawski.security.pkcs11.exceptions.DigestException;
import pl.mlodawski.security.pkcs11.jna.Cryptoki;
import pl.mlodawski.security.pkcs11.jna.constants.ReturnValue;
import pl.mlodawski.security.pkcs11.jna.structure.Mechanism;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class PKCS11DigestTest {

    @Mock
    private Cryptoki pkcs11Mock;

    private NativeLong session;
    private PKCS11Digest pkcs11Digest;

    @BeforeEach
    void setUp() {
        session = new NativeLong(1L);
        pkcs11Digest = new PKCS11Digest(pkcs11Mock, session);
    }

    @Test
    void constructor_nullPkcs11_shouldThrowIllegalArgumentException() {
        assertThrows(IllegalArgumentException.class, () -> new PKCS11Digest(null, session));
    }

    @Test
    void constructor_nullSession_shouldThrowIllegalArgumentException() {
        assertThrows(IllegalArgumentException.class, () -> new PKCS11Digest(pkcs11Mock, null));
    }

    @Test
    void digest_nullAlgorithm_shouldThrowIllegalArgumentException() {
        assertThrows(IllegalArgumentException.class, () ->
                pkcs11Digest.digest((PKCS11Digest.Algorithm) null, new byte[16]));
    }

    @Test
    void digest_nullData_shouldThrowIllegalArgumentException() {
        assertThrows(IllegalArgumentException.class, () ->
                pkcs11Digest.digest(PKCS11Digest.Algorithm.SHA256, null));
    }

    @Test
    void digest_nullAlgorithmName_shouldThrowIllegalArgumentException() {
        assertThrows(IllegalArgumentException.class, () ->
                pkcs11Digest.digest((String) null, new byte[16]));
    }

    @Test
    void digest_unknownAlgorithmName_shouldThrowIllegalArgumentException() {
        assertThrows(IllegalArgumentException.class, () ->
                pkcs11Digest.digest("UNKNOWN", new byte[16]));
    }

    @Test
    void digest_validInput_shouldReturnDigest() {
        byte[] data = "test data".getBytes();
        byte[] expectedDigest = new byte[32]; // SHA-256 length

        when(pkcs11Mock.C_DigestInit(any(NativeLong.class), any(Mechanism.class)))
                .thenReturn(new NativeLong(ReturnValue.OK));

        when(pkcs11Mock.C_Digest(any(NativeLong.class), any(byte[].class), any(NativeLong.class),
                isNull(), any(NativeLongByReference.class)))
                .thenAnswer(invocation -> {
                    NativeLongByReference lenRef = invocation.getArgument(4);
                    lenRef.setValue(new NativeLong(32));
                    return new NativeLong(ReturnValue.OK);
                });

        when(pkcs11Mock.C_Digest(any(NativeLong.class), any(byte[].class), any(NativeLong.class),
                any(byte[].class), any(NativeLongByReference.class)))
                .thenReturn(new NativeLong(ReturnValue.OK));

        byte[] result = pkcs11Digest.sha256(data);
        assertNotNull(result);
        assertEquals(32, result.length);
    }

    @Test
    void digest_digestInitFails_shouldThrowDigestException() {
        when(pkcs11Mock.C_DigestInit(any(NativeLong.class), any(Mechanism.class)))
                .thenReturn(new NativeLong(ReturnValue.FUNCTION_FAILED));

        assertThrows(DigestException.class, () ->
                pkcs11Digest.sha256("test".getBytes()));
    }

    @Test
    void digest_digestFails_shouldThrowDigestException() {
        when(pkcs11Mock.C_DigestInit(any(NativeLong.class), any(Mechanism.class)))
                .thenReturn(new NativeLong(ReturnValue.OK));

        when(pkcs11Mock.C_Digest(any(NativeLong.class), any(byte[].class), any(NativeLong.class),
                isNull(), any(NativeLongByReference.class)))
                .thenReturn(new NativeLong(ReturnValue.FUNCTION_FAILED));

        assertThrows(DigestException.class, () ->
                pkcs11Digest.sha256("test".getBytes()));
    }

    @Test
    void sha1_shouldCallDigestWithSHA1() {
        setupSuccessfulDigest(20);
        byte[] result = pkcs11Digest.sha1("test".getBytes());
        assertEquals(20, result.length);
    }

    @Test
    void sha384_shouldCallDigestWithSHA384() {
        setupSuccessfulDigest(48);
        byte[] result = pkcs11Digest.sha384("test".getBytes());
        assertEquals(48, result.length);
    }

    @Test
    void sha512_shouldCallDigestWithSHA512() {
        setupSuccessfulDigest(64);
        byte[] result = pkcs11Digest.sha512("test".getBytes());
        assertEquals(64, result.length);
    }

    @Test
    void md5_shouldCallDigestWithMD5() {
        setupSuccessfulDigest(16);
        byte[] result = pkcs11Digest.md5("test".getBytes());
        assertEquals(16, result.length);
    }

    @Test
    void ripemd160_shouldCallDigestWithRIPEMD160() {
        setupSuccessfulDigest(20);
        byte[] result = pkcs11Digest.ripemd160("test".getBytes());
        assertEquals(20, result.length);
    }

    @Test
    void digest_withStringAlgorithm_shouldWork() {
        setupSuccessfulDigest(32);
        byte[] result = pkcs11Digest.digest("SHA-256", "test".getBytes());
        assertEquals(32, result.length);
    }

    @Test
    void toHex_shouldConvertToHexString() {
        byte[] digest = {0x01, 0x23, 0x45, 0x67, (byte) 0x89, (byte) 0xAB, (byte) 0xCD, (byte) 0xEF};
        String hex = PKCS11Digest.toHex(digest);
        assertEquals("0123456789abcdef", hex);
    }

    @Test
    void toHex_nullDigest_shouldThrowIllegalArgumentException() {
        assertThrows(IllegalArgumentException.class, () -> PKCS11Digest.toHex(null));
    }

    private void setupSuccessfulDigest(int digestLength) {
        when(pkcs11Mock.C_DigestInit(any(NativeLong.class), any(Mechanism.class)))
                .thenReturn(new NativeLong(ReturnValue.OK));

        when(pkcs11Mock.C_Digest(any(NativeLong.class), any(byte[].class), any(NativeLong.class),
                isNull(), any(NativeLongByReference.class)))
                .thenAnswer(invocation -> {
                    NativeLongByReference lenRef = invocation.getArgument(4);
                    lenRef.setValue(new NativeLong(digestLength));
                    return new NativeLong(ReturnValue.OK);
                });

        when(pkcs11Mock.C_Digest(any(NativeLong.class), any(byte[].class), any(NativeLong.class),
                any(byte[].class), any(NativeLongByReference.class)))
                .thenReturn(new NativeLong(ReturnValue.OK));
    }
}
