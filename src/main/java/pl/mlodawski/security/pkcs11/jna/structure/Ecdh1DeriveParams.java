package pl.mlodawski.security.pkcs11.jna.structure;

import com.sun.jna.Memory;
import com.sun.jna.NativeLong;
import com.sun.jna.Pointer;
import com.sun.jna.Structure;

/**
 * PKCS#11 CK_ECDH1_DERIVE_PARAMS structure.
 * Parameters for ECDH key derivation mechanism.
 * Based on OASIS PKCS#11 specification.
 */
@Structure.FieldOrder({"kdf", "ulSharedDataLen", "pSharedData", "ulPublicDataLen", "pPublicData"})
public class Ecdh1DeriveParams extends Structure {

    /**
     * Key Derivation Function types for ECDH.
     */
    public static final long KDF_NULL = 0x00000001L;
    public static final long KDF_SHA1 = 0x00000002L;
    public static final long KDF_SHA224 = 0x00000005L;
    public static final long KDF_SHA256 = 0x00000006L;
    public static final long KDF_SHA384 = 0x00000007L;
    public static final long KDF_SHA512 = 0x00000008L;

    /**
     * Key derivation function used on the shared secret.
     */
    public NativeLong kdf;

    /**
     * Length of shared data in bytes.
     */
    public NativeLong ulSharedDataLen;

    /**
     * Pointer to optional shared data.
     */
    public Pointer pSharedData;

    /**
     * Length of peer's public key data in bytes.
     */
    public NativeLong ulPublicDataLen;

    /**
     * Pointer to peer's public key (EC point in uncompressed format).
     */
    public Pointer pPublicData;

    private Memory publicDataMemory;
    private Memory sharedDataMemory;

    public Ecdh1DeriveParams() {
        super();
    }

    /**
     * Creates ECDH derive parameters with peer's public key.
     *
     * @param kdf           key derivation function
     * @param publicKeyData peer's public key (EC point)
     */
    public Ecdh1DeriveParams(long kdf, byte[] publicKeyData) {
        this(kdf, publicKeyData, null);
    }

    /**
     * Creates ECDH derive parameters with peer's public key and shared data.
     *
     * @param kdf           key derivation function
     * @param publicKeyData peer's public key (EC point)
     * @param sharedData    optional shared data (can be null)
     */
    public Ecdh1DeriveParams(long kdf, byte[] publicKeyData, byte[] sharedData) {
        super();
        this.kdf = new NativeLong(kdf);

        if (publicKeyData != null && publicKeyData.length > 0) {
            this.publicDataMemory = new Memory(publicKeyData.length);
            this.publicDataMemory.write(0, publicKeyData, 0, publicKeyData.length);
            this.pPublicData = publicDataMemory;
            this.ulPublicDataLen = new NativeLong(publicKeyData.length);
        } else {
            this.pPublicData = null;
            this.ulPublicDataLen = new NativeLong(0);
        }

        if (sharedData != null && sharedData.length > 0) {
            this.sharedDataMemory = new Memory(sharedData.length);
            this.sharedDataMemory.write(0, sharedData, 0, sharedData.length);
            this.pSharedData = sharedDataMemory;
            this.ulSharedDataLen = new NativeLong(sharedData.length);
        } else {
            this.pSharedData = null;
            this.ulSharedDataLen = new NativeLong(0);
        }
    }

    /**
     * Creates ECDH derive parameters using NULL KDF (raw shared secret).
     *
     * @param publicKeyData peer's public key (EC point)
     */
    public static Ecdh1DeriveParams withNullKdf(byte[] publicKeyData) {
        return new Ecdh1DeriveParams(KDF_NULL, publicKeyData);
    }

    /**
     * Creates ECDH derive parameters using SHA-1 KDF.
     *
     * @param publicKeyData peer's public key (EC point)
     */
    public static Ecdh1DeriveParams withSha1Kdf(byte[] publicKeyData) {
        return new Ecdh1DeriveParams(KDF_SHA1, publicKeyData);
    }

    /**
     * Creates ECDH derive parameters using SHA-256 KDF.
     *
     * @param publicKeyData peer's public key (EC point)
     */
    public static Ecdh1DeriveParams withSha256Kdf(byte[] publicKeyData) {
        return new Ecdh1DeriveParams(KDF_SHA256, publicKeyData);
    }

    public static class ByReference extends Ecdh1DeriveParams implements Structure.ByReference {}
    public static class ByValue extends Ecdh1DeriveParams implements Structure.ByValue {}
}
