package pl.mlodawski.security.pkcs11;

import com.sun.jna.Memory;
import com.sun.jna.Native;
import com.sun.jna.NativeLong;
import com.sun.jna.Pointer;
import com.sun.jna.ptr.NativeLongByReference;
import lombok.extern.slf4j.Slf4j;
import pl.mlodawski.security.pkcs11.exceptions.KeyDerivationException;
import pl.mlodawski.security.pkcs11.jna.Cryptoki;
import pl.mlodawski.security.pkcs11.jna.constants.AttributeType;
import pl.mlodawski.security.pkcs11.jna.constants.MechanismType;
import pl.mlodawski.security.pkcs11.jna.constants.ObjectClass;
import pl.mlodawski.security.pkcs11.jna.constants.ReturnValue;
import pl.mlodawski.security.pkcs11.jna.structure.Ecdh1DeriveParams;
import pl.mlodawski.security.pkcs11.jna.structure.Mechanism;

import java.security.interfaces.ECPublicKey;

/**
 * Provides ECDH (Elliptic Curve Diffie-Hellman) key derivation
 * operations using PKCS#11 hardware tokens.
 *
 * ECDH allows two parties to establish a shared secret over an
 * insecure channel, which can then be used for symmetric encryption.
 */
@Slf4j
public class PKCS11KeyDerivation {

    /**
     * Key derivation functions available for ECDH.
     */
    public enum KeyDerivationFunction {
        /** No KDF - raw shared secret */
        NULL(Ecdh1DeriveParams.KDF_NULL),
        /** SHA-1 based KDF */
        SHA1(Ecdh1DeriveParams.KDF_SHA1),
        /** SHA-256 based KDF */
        SHA256(Ecdh1DeriveParams.KDF_SHA256),
        /** SHA-384 based KDF */
        SHA384(Ecdh1DeriveParams.KDF_SHA384),
        /** SHA-512 based KDF */
        SHA512(Ecdh1DeriveParams.KDF_SHA512);

        private final long value;

        KeyDerivationFunction(long value) {
            this.value = value;
        }

        public long getValue() {
            return value;
        }
    }

    /**
     * Type of the derived key.
     */
    public enum DerivedKeyType {
        /** Generic secret key */
        GENERIC_SECRET(0x10L),
        /** AES key */
        AES(0x1FL);

        private final long value;

        DerivedKeyType(long value) {
            this.value = value;
        }

        public long getValue() {
            return value;
        }
    }

    /**
     * Derives a shared secret using ECDH.
     *
     * @param pkcs11             the PKCS#11 interface
     * @param session            the session handle
     * @param ecPrivateKeyHandle handle to EC private key on the token
     * @param peerPublicKeyData  peer's public key as EC point (uncompressed format: 0x04 || X || Y)
     * @param derivedKeyLength   length of the derived key in bytes
     * @return handle to the derived secret key on the token
     */
    public NativeLong deriveKey(Cryptoki pkcs11, NativeLong session, NativeLong ecPrivateKeyHandle,
                                byte[] peerPublicKeyData, int derivedKeyLength) {
        return deriveKey(pkcs11, session, ecPrivateKeyHandle, peerPublicKeyData, derivedKeyLength,
                KeyDerivationFunction.NULL, DerivedKeyType.GENERIC_SECRET);
    }

    /**
     * Derives a shared secret using ECDH with specified KDF and key type.
     *
     * @param pkcs11             the PKCS#11 interface
     * @param session            the session handle
     * @param ecPrivateKeyHandle handle to EC private key on the token
     * @param peerPublicKeyData  peer's public key as EC point
     * @param derivedKeyLength   length of the derived key in bytes
     * @param kdf                key derivation function to use
     * @param keyType            type of the derived key
     * @return handle to the derived secret key on the token
     */
    public NativeLong deriveKey(Cryptoki pkcs11, NativeLong session, NativeLong ecPrivateKeyHandle,
                                byte[] peerPublicKeyData, int derivedKeyLength,
                                KeyDerivationFunction kdf, DerivedKeyType keyType) {
        validateParameters(pkcs11, session, ecPrivateKeyHandle, peerPublicKeyData, derivedKeyLength);

        try {
            Ecdh1DeriveParams params = new Ecdh1DeriveParams(kdf.getValue(), peerPublicKeyData);
            Mechanism mechanism = new Mechanism(MechanismType.ECDH1_DERIVE, params);

            Pointer template = createDerivedKeyTemplate(keyType, derivedKeyLength);

            NativeLongByReference derivedKeyHandle = new NativeLongByReference();
            NativeLong rv = pkcs11.C_DeriveKey(session, mechanism, ecPrivateKeyHandle,
                    template, new NativeLong(4), derivedKeyHandle);

            if (!ReturnValue.isSuccess(rv)) {
                throw new KeyDerivationException(
                        "C_DeriveKey failed with error code: 0x" + Long.toHexString(rv.longValue()), null);
            }

            log.debug("Derived {} byte key using ECDH with KDF: {}", derivedKeyLength, kdf.name());
            return derivedKeyHandle.getValue();

        } catch (KeyDerivationException e) {
            throw e;
        } catch (Exception e) {
            log.error("Error during ECDH key derivation", e);
            throw new KeyDerivationException("Error during ECDH key derivation", e);
        }
    }

    /**
     * Derives a shared secret using ECDH with cofactor multiplication.
     * Cofactor ECDH provides additional protection against some attacks.
     *
     * @param pkcs11             the PKCS#11 interface
     * @param session            the session handle
     * @param ecPrivateKeyHandle handle to EC private key on the token
     * @param peerPublicKeyData  peer's public key as EC point
     * @param derivedKeyLength   length of the derived key in bytes
     * @return handle to the derived secret key on the token
     */
    public NativeLong deriveKeyWithCofactor(Cryptoki pkcs11, NativeLong session, NativeLong ecPrivateKeyHandle,
                                            byte[] peerPublicKeyData, int derivedKeyLength) {
        validateParameters(pkcs11, session, ecPrivateKeyHandle, peerPublicKeyData, derivedKeyLength);

        try {
            Ecdh1DeriveParams params = Ecdh1DeriveParams.withNullKdf(peerPublicKeyData);
            Mechanism mechanism = new Mechanism(MechanismType.ECDH1_COFACTOR_DERIVE, params);

            Pointer template = createDerivedKeyTemplate(DerivedKeyType.GENERIC_SECRET, derivedKeyLength);

            NativeLongByReference derivedKeyHandle = new NativeLongByReference();
            NativeLong rv = pkcs11.C_DeriveKey(session, mechanism, ecPrivateKeyHandle,
                    template, new NativeLong(4), derivedKeyHandle);

            if (!ReturnValue.isSuccess(rv)) {
                throw new KeyDerivationException(
                        "C_DeriveKey (cofactor) failed with error code: 0x" + Long.toHexString(rv.longValue()), null);
            }

            log.debug("Derived {} byte key using ECDH with cofactor", derivedKeyLength);
            return derivedKeyHandle.getValue();

        } catch (KeyDerivationException e) {
            throw e;
        } catch (Exception e) {
            log.error("Error during ECDH cofactor key derivation", e);
            throw new KeyDerivationException("Error during ECDH cofactor key derivation", e);
        }
    }

    /**
     * Extracts EC point data from an ECPublicKey in uncompressed format.
     * The format is: 0x04 || X || Y
     *
     * @param publicKey the EC public key
     * @return EC point bytes in uncompressed format
     */
    public static byte[] extractEcPoint(ECPublicKey publicKey) {
        if (publicKey == null) {
            throw new IllegalArgumentException("publicKey cannot be null");
        }

        byte[] x = publicKey.getW().getAffineX().toByteArray();
        byte[] y = publicKey.getW().getAffineY().toByteArray();

        int fieldSize = (publicKey.getParams().getCurve().getField().getFieldSize() + 7) / 8;

        byte[] ecPoint = new byte[1 + 2 * fieldSize];
        ecPoint[0] = 0x04;

        int xStart = x.length > fieldSize ? x.length - fieldSize : 0;
        int xDest = 1 + (fieldSize - Math.min(x.length, fieldSize));
        System.arraycopy(x, xStart, ecPoint, xDest, Math.min(x.length, fieldSize));

        int yStart = y.length > fieldSize ? y.length - fieldSize : 0;
        int yDest = 1 + fieldSize + (fieldSize - Math.min(y.length, fieldSize));
        System.arraycopy(y, yStart, ecPoint, yDest, Math.min(y.length, fieldSize));

        return ecPoint;
    }

    private Pointer createDerivedKeyTemplate(DerivedKeyType keyType, int keyLength) {
        int attrSize = NativeLong.SIZE + Native.POINTER_SIZE + NativeLong.SIZE;
        int numAttrs = 4;
        Memory template = new Memory((long) attrSize * numAttrs);
        template.clear();

        int offset = 0;

        Memory classValue = new Memory(NativeLong.SIZE);
        classValue.setNativeLong(0, new NativeLong(ObjectClass.SECRET_KEY));
        template.setNativeLong(offset, new NativeLong(AttributeType.CLASS));
        template.setPointer(offset + NativeLong.SIZE, classValue);
        template.setNativeLong(offset + NativeLong.SIZE + Native.POINTER_SIZE, new NativeLong(NativeLong.SIZE));
        offset += attrSize;

        Memory keyTypeValue = new Memory(NativeLong.SIZE);
        keyTypeValue.setNativeLong(0, new NativeLong(keyType.getValue()));
        template.setNativeLong(offset, new NativeLong(AttributeType.KEY_TYPE));
        template.setPointer(offset + NativeLong.SIZE, keyTypeValue);
        template.setNativeLong(offset + NativeLong.SIZE + Native.POINTER_SIZE, new NativeLong(NativeLong.SIZE));
        offset += attrSize;

        Memory valueLenValue = new Memory(NativeLong.SIZE);
        valueLenValue.setNativeLong(0, new NativeLong(keyLength));
        template.setNativeLong(offset, new NativeLong(AttributeType.VALUE_LEN));
        template.setPointer(offset + NativeLong.SIZE, valueLenValue);
        template.setNativeLong(offset + NativeLong.SIZE + Native.POINTER_SIZE, new NativeLong(NativeLong.SIZE));
        offset += attrSize;

        Memory extractableValue = new Memory(1);
        extractableValue.setByte(0, (byte) 1);
        template.setNativeLong(offset, new NativeLong(AttributeType.EXTRACTABLE));
        template.setPointer(offset + NativeLong.SIZE, extractableValue);
        template.setNativeLong(offset + NativeLong.SIZE + Native.POINTER_SIZE, new NativeLong(1));

        return template;
    }

    private void validateParameters(Cryptoki pkcs11, NativeLong session, NativeLong ecPrivateKeyHandle,
                                    byte[] peerPublicKeyData, int derivedKeyLength) {
        if (pkcs11 == null) {
            throw new IllegalArgumentException("pkcs11 cannot be null");
        }
        if (session == null) {
            throw new IllegalArgumentException("session cannot be null");
        }
        if (ecPrivateKeyHandle == null) {
            throw new IllegalArgumentException("ecPrivateKeyHandle cannot be null");
        }
        if (peerPublicKeyData == null || peerPublicKeyData.length == 0) {
            throw new IllegalArgumentException("peerPublicKeyData cannot be null or empty");
        }
        if (derivedKeyLength <= 0) {
            throw new IllegalArgumentException("derivedKeyLength must be positive");
        }
    }
}
