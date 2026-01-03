package pl.mlodawski.security.pkcs11.jna.structure;

import com.sun.jna.Memory;
import com.sun.jna.NativeLong;
import com.sun.jna.Pointer;
import com.sun.jna.Structure;
import pl.mlodawski.security.pkcs11.jna.constants.MechanismType;

/**
 * PKCS#11 CK_RSA_PKCS_PSS_PARAMS structure.
 * Parameters for RSA-PSS signature mechanism.
 * Based on OASIS PKCS#11 specification.
 */
@Structure.FieldOrder({"hashAlg", "mgf", "sLen"})
public class RsaPkcsPssParams extends Structure {

    /**
     * MGF (Mask Generation Function) types for RSA-PSS.
     */
    public static final long MGF1_SHA1 = 0x00000001L;
    public static final long MGF1_SHA224 = 0x00000005L;
    public static final long MGF1_SHA256 = 0x00000002L;
    public static final long MGF1_SHA384 = 0x00000003L;
    public static final long MGF1_SHA512 = 0x00000004L;

    /**
     * Hash algorithm used in the PSS encoding (CKM_* value).
     */
    public NativeLong hashAlg;

    /**
     * Mask generation function to use (CKG_MGF1_* value).
     */
    public NativeLong mgf;

    /**
     * Length of the salt value in bytes.
     */
    public NativeLong sLen;

    public RsaPkcsPssParams() {
        super();
    }

    /**
     * Creates RSA-PSS parameters with specified hash algorithm.
     *
     * @param hashAlg   the hash algorithm (CKM_SHA256, CKM_SHA384, etc.)
     * @param mgf       the mask generation function (MGF1_SHA256, etc.)
     * @param saltLen   the salt length in bytes (usually same as hash output length)
     */
    public RsaPkcsPssParams(long hashAlg, long mgf, long saltLen) {
        super();
        this.hashAlg = new NativeLong(hashAlg);
        this.mgf = new NativeLong(mgf);
        this.sLen = new NativeLong(saltLen);
        write();
    }

    /**
     * Creates RSA-PSS parameters as raw memory block.
     * This is more reliable for passing to native code.
     */
    public static Pointer createAsMemory(long hashAlg, long mgf, long saltLen) {
        Memory mem = new Memory(3L * NativeLong.SIZE);
        int offset = 0;
        mem.setNativeLong(offset, new NativeLong(hashAlg));
        offset += NativeLong.SIZE;
        mem.setNativeLong(offset, new NativeLong(mgf));
        offset += NativeLong.SIZE;
        mem.setNativeLong(offset, new NativeLong(saltLen));
        return mem;
    }

    /**
     * Gets the size of the CK_RSA_PKCS_PSS_PARAMS structure.
     */
    public static int getStructSize() {
        return 3 * NativeLong.SIZE;
    }

    /**
     * Creates RSA-PSS parameters for SHA-256.
     * Uses MGF1-SHA256 and salt length of 32 bytes.
     */
    public static RsaPkcsPssParams sha256() {
        return new RsaPkcsPssParams(MechanismType.SHA256, MGF1_SHA256, 32);
    }

    /**
     * Creates RSA-PSS parameters for SHA-384.
     * Uses MGF1-SHA384 and salt length of 48 bytes.
     */
    public static RsaPkcsPssParams sha384() {
        return new RsaPkcsPssParams(MechanismType.SHA384, MGF1_SHA384, 48);
    }

    /**
     * Creates RSA-PSS parameters for SHA-512.
     * Uses MGF1-SHA512 and salt length of 64 bytes.
     */
    public static RsaPkcsPssParams sha512() {
        return new RsaPkcsPssParams(MechanismType.SHA512, MGF1_SHA512, 64);
    }

    /**
     * Creates RSA-PSS parameters for SHA-1.
     * Uses MGF1-SHA1 and salt length of 20 bytes.
     */
    public static RsaPkcsPssParams sha1() {
        return new RsaPkcsPssParams(MechanismType.SHA_1, MGF1_SHA1, 20);
    }

    /**
     * Creates RSA-PSS parameters for SHA-224.
     * Uses MGF1-SHA224 and salt length of 28 bytes.
     */
    public static RsaPkcsPssParams sha224() {
        return new RsaPkcsPssParams(MechanismType.SHA224, MGF1_SHA224, 28);
    }

    public static class ByReference extends RsaPkcsPssParams implements Structure.ByReference {}
    public static class ByValue extends RsaPkcsPssParams implements Structure.ByValue {}
}
