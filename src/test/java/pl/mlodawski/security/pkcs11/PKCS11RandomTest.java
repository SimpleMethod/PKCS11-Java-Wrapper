package pl.mlodawski.security.pkcs11;

import com.sun.jna.NativeLong;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import pl.mlodawski.security.pkcs11.exceptions.RandomGenerationException;
import pl.mlodawski.security.pkcs11.jna.Cryptoki;
import pl.mlodawski.security.pkcs11.jna.constants.ReturnValue;

import java.util.Arrays;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class PKCS11RandomTest {

    @Mock
    private Cryptoki pkcs11Mock;

    private NativeLong session;
    private PKCS11Random pkcs11Random;

    @BeforeEach
    void setUp() {
        session = new NativeLong(1L);
        pkcs11Random = new PKCS11Random(pkcs11Mock, session);
    }

    @Test
    void constructor_nullPkcs11_shouldThrowIllegalArgumentException() {
        assertThrows(IllegalArgumentException.class, () -> new PKCS11Random(null, session));
    }

    @Test
    void constructor_nullSession_shouldThrowIllegalArgumentException() {
        assertThrows(IllegalArgumentException.class, () -> new PKCS11Random(pkcs11Mock, null));
    }

    @Test
    void nextBytes_nullBytes_shouldThrowIllegalArgumentException() {
        assertThrows(IllegalArgumentException.class, () -> pkcs11Random.nextBytes(null));
    }

    @Test
    void nextBytes_emptyBytes_shouldNotCallPkcs11() {
        byte[] bytes = new byte[0];
        pkcs11Random.nextBytes(bytes);
        verify(pkcs11Mock, never()).C_GenerateRandom(any(), any(), any());
    }

    @Test
    void nextBytes_validInput_shouldCallPkcs11() {
        when(pkcs11Mock.C_GenerateRandom(any(NativeLong.class), any(byte[].class), any(NativeLong.class)))
                .thenReturn(new NativeLong(ReturnValue.OK));

        byte[] bytes = new byte[16];
        pkcs11Random.nextBytes(bytes);

        verify(pkcs11Mock).C_GenerateRandom(eq(session), eq(bytes), any(NativeLong.class));
    }

    @Test
    void nextBytes_pkcs11Fails_shouldThrowRandomGenerationException() {
        when(pkcs11Mock.C_GenerateRandom(any(NativeLong.class), any(byte[].class), any(NativeLong.class)))
                .thenReturn(new NativeLong(ReturnValue.FUNCTION_FAILED));

        byte[] bytes = new byte[16];
        assertThrows(RandomGenerationException.class, () -> pkcs11Random.nextBytes(bytes));
    }

    @Test
    void generateRandomBytes_negativeNumber_shouldThrowIllegalArgumentException() {
        assertThrows(IllegalArgumentException.class, () -> pkcs11Random.generateRandomBytes(-1));
    }

    @Test
    void generateRandomBytes_zero_shouldReturnEmptyArray() {
        byte[] result = pkcs11Random.generateRandomBytes(0);
        assertEquals(0, result.length);
    }

    @Test
    void generateRandomBytes_validInput_shouldReturnByteArray() {
        when(pkcs11Mock.C_GenerateRandom(any(NativeLong.class), any(byte[].class), any(NativeLong.class)))
                .thenReturn(new NativeLong(ReturnValue.OK));

        byte[] result = pkcs11Random.generateRandomBytes(32);
        assertEquals(32, result.length);
    }

    @Test
    void nextInt_shouldReturnInteger() {
        when(pkcs11Mock.C_GenerateRandom(any(NativeLong.class), any(byte[].class), any(NativeLong.class)))
                .thenAnswer(invocation -> {
                    byte[] bytes = invocation.getArgument(1);
                    for (int i = 0; i < bytes.length; i++) {
                        bytes[i] = (byte) (i + 1);
                    }
                    return new NativeLong(ReturnValue.OK);
                });

        int result = pkcs11Random.nextInt();
        assertNotEquals(0, result);
    }

    @Test
    void nextLong_shouldReturnLong() {
        when(pkcs11Mock.C_GenerateRandom(any(NativeLong.class), any(byte[].class), any(NativeLong.class)))
                .thenAnswer(invocation -> {
                    byte[] bytes = invocation.getArgument(1);
                    for (int i = 0; i < bytes.length; i++) {
                        bytes[i] = (byte) (i + 1);
                    }
                    return new NativeLong(ReturnValue.OK);
                });

        long result = pkcs11Random.nextLong();
        assertNotEquals(0L, result);
    }

    @Test
    void nextBoolean_shouldReturnBoolean() {
        when(pkcs11Mock.C_GenerateRandom(any(NativeLong.class), any(byte[].class), any(NativeLong.class)))
                .thenReturn(new NativeLong(ReturnValue.OK));

        // Just verify it doesn't throw
        pkcs11Random.nextBoolean();
        verify(pkcs11Mock).C_GenerateRandom(any(), any(), any());
    }

    @Test
    void nextDouble_shouldReturnDoubleBetweenZeroAndOne() {
        when(pkcs11Mock.C_GenerateRandom(any(NativeLong.class), any(byte[].class), any(NativeLong.class)))
                .thenAnswer(invocation -> {
                    byte[] bytes = invocation.getArgument(1);
                    Arrays.fill(bytes, (byte) 0x7F);
                    return new NativeLong(ReturnValue.OK);
                });

        double result = pkcs11Random.nextDouble();
        assertTrue(result >= 0.0 && result < 1.0);
    }

    @Test
    void nextFloat_shouldReturnFloatBetweenZeroAndOne() {
        when(pkcs11Mock.C_GenerateRandom(any(NativeLong.class), any(byte[].class), any(NativeLong.class)))
                .thenAnswer(invocation -> {
                    byte[] bytes = invocation.getArgument(1);
                    Arrays.fill(bytes, (byte) 0x7F);
                    return new NativeLong(ReturnValue.OK);
                });

        float result = pkcs11Random.nextFloat();
        assertTrue(result >= 0.0f && result < 1.0f);
    }

    @Test
    void getAlgorithm_shouldReturnPKCS11HardwareRNG() {
        assertEquals("PKCS11-HardwareRNG", pkcs11Random.getAlgorithm());
    }
}
