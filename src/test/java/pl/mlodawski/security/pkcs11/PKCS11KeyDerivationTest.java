package pl.mlodawski.security.pkcs11;

import com.sun.jna.NativeLong;
import com.sun.jna.Pointer;
import com.sun.jna.ptr.NativeLongByReference;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import pl.mlodawski.security.pkcs11.exceptions.KeyDerivationException;
import pl.mlodawski.security.pkcs11.jna.Cryptoki;
import pl.mlodawski.security.pkcs11.jna.structure.Mechanism;

import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECGenParameterSpec;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
@DisplayName("PKCS11KeyDerivation Tests")
class PKCS11KeyDerivationTest {

    @Mock
    private Cryptoki mockPkcs11;

    private PKCS11KeyDerivation keyDerivation;
    private NativeLong session;
    private NativeLong privateKeyHandle;
    private byte[] peerPublicKeyData;

    @BeforeEach
    void setUp() {
        keyDerivation = new PKCS11KeyDerivation();
        session = new NativeLong(1);
        privateKeyHandle = new NativeLong(100);
        // Sample EC point data (uncompressed format: 0x04 || X || Y for P-256)
        peerPublicKeyData = new byte[65];
        peerPublicKeyData[0] = 0x04;
        for (int i = 1; i < 65; i++) {
            peerPublicKeyData[i] = (byte) i;
        }
    }

    @Nested
    @DisplayName("Parameter validation tests")
    class ValidationTests {

        @Test
        @DisplayName("Should throw exception when pkcs11 is null")
        void shouldThrowExceptionWhenPkcs11IsNull() {
            IllegalArgumentException exception = assertThrows(IllegalArgumentException.class,
                    () -> keyDerivation.deriveKey(null, session, privateKeyHandle, peerPublicKeyData, 32));
            assertEquals("pkcs11 cannot be null", exception.getMessage());
        }

        @Test
        @DisplayName("Should throw exception when session is null")
        void shouldThrowExceptionWhenSessionIsNull() {
            IllegalArgumentException exception = assertThrows(IllegalArgumentException.class,
                    () -> keyDerivation.deriveKey(mockPkcs11, null, privateKeyHandle, peerPublicKeyData, 32));
            assertEquals("session cannot be null", exception.getMessage());
        }

        @Test
        @DisplayName("Should throw exception when private key handle is null")
        void shouldThrowExceptionWhenPrivateKeyHandleIsNull() {
            IllegalArgumentException exception = assertThrows(IllegalArgumentException.class,
                    () -> keyDerivation.deriveKey(mockPkcs11, session, null, peerPublicKeyData, 32));
            assertEquals("ecPrivateKeyHandle cannot be null", exception.getMessage());
        }

        @Test
        @DisplayName("Should throw exception when peer public key data is null")
        void shouldThrowExceptionWhenPeerPublicKeyDataIsNull() {
            IllegalArgumentException exception = assertThrows(IllegalArgumentException.class,
                    () -> keyDerivation.deriveKey(mockPkcs11, session, privateKeyHandle, null, 32));
            assertEquals("peerPublicKeyData cannot be null or empty", exception.getMessage());
        }

        @Test
        @DisplayName("Should throw exception when peer public key data is empty")
        void shouldThrowExceptionWhenPeerPublicKeyDataIsEmpty() {
            IllegalArgumentException exception = assertThrows(IllegalArgumentException.class,
                    () -> keyDerivation.deriveKey(mockPkcs11, session, privateKeyHandle, new byte[0], 32));
            assertEquals("peerPublicKeyData cannot be null or empty", exception.getMessage());
        }

        @Test
        @DisplayName("Should throw exception when derived key length is zero")
        void shouldThrowExceptionWhenDerivedKeyLengthIsZero() {
            IllegalArgumentException exception = assertThrows(IllegalArgumentException.class,
                    () -> keyDerivation.deriveKey(mockPkcs11, session, privateKeyHandle, peerPublicKeyData, 0));
            assertEquals("derivedKeyLength must be positive", exception.getMessage());
        }

        @Test
        @DisplayName("Should throw exception when derived key length is negative")
        void shouldThrowExceptionWhenDerivedKeyLengthIsNegative() {
            IllegalArgumentException exception = assertThrows(IllegalArgumentException.class,
                    () -> keyDerivation.deriveKey(mockPkcs11, session, privateKeyHandle, peerPublicKeyData, -1));
            assertEquals("derivedKeyLength must be positive", exception.getMessage());
        }
    }

    @Nested
    @DisplayName("Key derivation tests")
    class KeyDerivationTests {

        @Test
        @DisplayName("Should derive key with default parameters")
        void shouldDeriveKeyWithDefaultParameters() {
            NativeLong derivedKeyHandle = new NativeLong(200);

            when(mockPkcs11.C_DeriveKey(eq(session), any(Mechanism.class), eq(privateKeyHandle),
                    any(Pointer.class), any(NativeLong.class), any(NativeLongByReference.class)))
                    .thenAnswer(invocation -> {
                        NativeLongByReference handleRef = invocation.getArgument(5);
                        handleRef.setValue(derivedKeyHandle);
                        return new NativeLong(0); // CKR_OK
                    });

            NativeLong result = keyDerivation.deriveKey(mockPkcs11, session, privateKeyHandle, peerPublicKeyData, 32);

            assertEquals(derivedKeyHandle.longValue(), result.longValue());
            verify(mockPkcs11).C_DeriveKey(eq(session), any(Mechanism.class), eq(privateKeyHandle),
                    any(Pointer.class), eq(new NativeLong(4)), any(NativeLongByReference.class));
        }

        @Test
        @DisplayName("Should derive key with SHA256 KDF")
        void shouldDeriveKeyWithSha256Kdf() {
            NativeLong derivedKeyHandle = new NativeLong(201);

            when(mockPkcs11.C_DeriveKey(eq(session), any(Mechanism.class), eq(privateKeyHandle),
                    any(Pointer.class), any(NativeLong.class), any(NativeLongByReference.class)))
                    .thenAnswer(invocation -> {
                        NativeLongByReference handleRef = invocation.getArgument(5);
                        handleRef.setValue(derivedKeyHandle);
                        return new NativeLong(0); // CKR_OK
                    });

            NativeLong result = keyDerivation.deriveKey(mockPkcs11, session, privateKeyHandle, peerPublicKeyData, 32,
                    PKCS11KeyDerivation.KeyDerivationFunction.SHA256,
                    PKCS11KeyDerivation.DerivedKeyType.AES);

            assertEquals(derivedKeyHandle.longValue(), result.longValue());
        }

        @Test
        @DisplayName("Should derive key with cofactor multiplication")
        void shouldDeriveKeyWithCofactor() {
            NativeLong derivedKeyHandle = new NativeLong(202);

            when(mockPkcs11.C_DeriveKey(eq(session), any(Mechanism.class), eq(privateKeyHandle),
                    any(Pointer.class), any(NativeLong.class), any(NativeLongByReference.class)))
                    .thenAnswer(invocation -> {
                        NativeLongByReference handleRef = invocation.getArgument(5);
                        handleRef.setValue(derivedKeyHandle);
                        return new NativeLong(0); // CKR_OK
                    });

            NativeLong result = keyDerivation.deriveKeyWithCofactor(mockPkcs11, session, privateKeyHandle, peerPublicKeyData, 32);

            assertEquals(derivedKeyHandle.longValue(), result.longValue());
        }

        @Test
        @DisplayName("Should throw KeyDerivationException on PKCS11 error")
        void shouldThrowKeyDerivationExceptionOnPkcs11Error() {
            when(mockPkcs11.C_DeriveKey(eq(session), any(Mechanism.class), eq(privateKeyHandle),
                    any(Pointer.class), any(NativeLong.class), any(NativeLongByReference.class)))
                    .thenReturn(new NativeLong(0x00000030)); // CKR_DEVICE_ERROR

            KeyDerivationException exception = assertThrows(KeyDerivationException.class,
                    () -> keyDerivation.deriveKey(mockPkcs11, session, privateKeyHandle, peerPublicKeyData, 32));

            assertTrue(exception.getMessage().contains("C_DeriveKey failed"));
            assertTrue(exception.getMessage().contains("0x30"));
        }

        @Test
        @DisplayName("Should throw KeyDerivationException on cofactor derivation error")
        void shouldThrowKeyDerivationExceptionOnCofactorError() {
            when(mockPkcs11.C_DeriveKey(eq(session), any(Mechanism.class), eq(privateKeyHandle),
                    any(Pointer.class), any(NativeLong.class), any(NativeLongByReference.class)))
                    .thenReturn(new NativeLong(0x00000070)); // CKR_MECHANISM_INVALID

            KeyDerivationException exception = assertThrows(KeyDerivationException.class,
                    () -> keyDerivation.deriveKeyWithCofactor(mockPkcs11, session, privateKeyHandle, peerPublicKeyData, 32));

            assertTrue(exception.getMessage().contains("C_DeriveKey (cofactor) failed"));
        }
    }

    @Nested
    @DisplayName("KeyDerivationFunction enum tests")
    class KdfEnumTests {

        @Test
        @DisplayName("NULL KDF should have correct value")
        void nullKdfShouldHaveCorrectValue() {
            assertEquals(0x00000001L, PKCS11KeyDerivation.KeyDerivationFunction.NULL.getValue());
        }

        @Test
        @DisplayName("SHA1 KDF should have correct value")
        void sha1KdfShouldHaveCorrectValue() {
            assertEquals(0x00000002L, PKCS11KeyDerivation.KeyDerivationFunction.SHA1.getValue());
        }

        @Test
        @DisplayName("SHA256 KDF should have correct value")
        void sha256KdfShouldHaveCorrectValue() {
            assertEquals(0x00000006L, PKCS11KeyDerivation.KeyDerivationFunction.SHA256.getValue());
        }

        @Test
        @DisplayName("SHA384 KDF should have correct value")
        void sha384KdfShouldHaveCorrectValue() {
            assertEquals(0x00000007L, PKCS11KeyDerivation.KeyDerivationFunction.SHA384.getValue());
        }

        @Test
        @DisplayName("SHA512 KDF should have correct value")
        void sha512KdfShouldHaveCorrectValue() {
            assertEquals(0x00000008L, PKCS11KeyDerivation.KeyDerivationFunction.SHA512.getValue());
        }
    }

    @Nested
    @DisplayName("DerivedKeyType enum tests")
    class DerivedKeyTypeEnumTests {

        @Test
        @DisplayName("GENERIC_SECRET should have correct value")
        void genericSecretShouldHaveCorrectValue() {
            assertEquals(0x10L, PKCS11KeyDerivation.DerivedKeyType.GENERIC_SECRET.getValue());
        }

        @Test
        @DisplayName("AES should have correct value")
        void aesShouldHaveCorrectValue() {
            assertEquals(0x1FL, PKCS11KeyDerivation.DerivedKeyType.AES.getValue());
        }
    }

    @Nested
    @DisplayName("EC point extraction tests")
    class EcPointExtractionTests {

        @Test
        @DisplayName("Should throw exception when public key is null")
        void shouldThrowExceptionWhenPublicKeyIsNull() {
            IllegalArgumentException exception = assertThrows(IllegalArgumentException.class,
                    () -> PKCS11KeyDerivation.extractEcPoint(null));
            assertEquals("publicKey cannot be null", exception.getMessage());
        }

        @Test
        @DisplayName("Should extract EC point from P-256 key")
        void shouldExtractEcPointFromP256Key() throws Exception {
            KeyPairGenerator keyGen = KeyPairGenerator.getInstance("EC");
            keyGen.initialize(new ECGenParameterSpec("secp256r1"));
            KeyPair keyPair = keyGen.generateKeyPair();
            ECPublicKey ecPublicKey = (ECPublicKey) keyPair.getPublic();

            byte[] ecPoint = PKCS11KeyDerivation.extractEcPoint(ecPublicKey);

            // P-256 uncompressed point: 0x04 + 32 bytes X + 32 bytes Y = 65 bytes
            assertEquals(65, ecPoint.length);
            assertEquals(0x04, ecPoint[0] & 0xFF);
        }

        @Test
        @DisplayName("Should extract EC point from P-384 key")
        void shouldExtractEcPointFromP384Key() throws Exception {
            KeyPairGenerator keyGen = KeyPairGenerator.getInstance("EC");
            keyGen.initialize(new ECGenParameterSpec("secp384r1"));
            KeyPair keyPair = keyGen.generateKeyPair();
            ECPublicKey ecPublicKey = (ECPublicKey) keyPair.getPublic();

            byte[] ecPoint = PKCS11KeyDerivation.extractEcPoint(ecPublicKey);

            // P-384 uncompressed point: 0x04 + 48 bytes X + 48 bytes Y = 97 bytes
            assertEquals(97, ecPoint.length);
            assertEquals(0x04, ecPoint[0] & 0xFF);
        }

        @Test
        @DisplayName("Extracted EC point should contain correct coordinates")
        void extractedEcPointShouldContainCorrectCoordinates() throws Exception {
            KeyPairGenerator keyGen = KeyPairGenerator.getInstance("EC");
            keyGen.initialize(new ECGenParameterSpec("secp256r1"));
            KeyPair keyPair = keyGen.generateKeyPair();
            ECPublicKey ecPublicKey = (ECPublicKey) keyPair.getPublic();

            byte[] ecPoint = PKCS11KeyDerivation.extractEcPoint(ecPublicKey);

            // Extract X and Y from the EC point
            byte[] extractedX = new byte[32];
            byte[] extractedY = new byte[32];
            System.arraycopy(ecPoint, 1, extractedX, 0, 32);
            System.arraycopy(ecPoint, 33, extractedY, 0, 32);

            // Convert to BigInteger and compare with original
            BigInteger originalX = ecPublicKey.getW().getAffineX();
            BigInteger originalY = ecPublicKey.getW().getAffineY();

            // The extracted bytes (big-endian unsigned) should represent the same value
            BigInteger reconstructedX = new BigInteger(1, extractedX);
            BigInteger reconstructedY = new BigInteger(1, extractedY);

            assertEquals(originalX, reconstructedX);
            assertEquals(originalY, reconstructedY);
        }
    }
}
