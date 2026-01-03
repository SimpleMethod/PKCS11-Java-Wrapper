package pl.mlodawski.security.pkcs11.jna.structure;

import com.sun.jna.Memory;
import com.sun.jna.Native;
import com.sun.jna.NativeLong;
import com.sun.jna.Pointer;
import com.sun.jna.Structure;
import pl.mlodawski.security.pkcs11.jna.constants.MechanismType;

/**
 * PKCS#11 CK_RSA_PKCS_OAEP_PARAMS structure.
 * Parameters for RSA-OAEP encryption/decryption mechanism.
 * Based on OASIS PKCS#11 specification.
 */
@Structure.FieldOrder({"hashAlg", "mgf", "source", "pSourceData", "ulSourceDataLen"})
public class RsaPkcsOaepParams extends Structure {

    /**
     * MGF (Mask Generation Function) types for RSA-OAEP.
     */
    public static final long MGF1_SHA1 = 0x00000001L;
    public static final long MGF1_SHA224 = 0x00000005L;
    public static final long MGF1_SHA256 = 0x00000002L;
    public static final long MGF1_SHA384 = 0x00000003L;
    public static final long MGF1_SHA512 = 0x00000004L;

    /**
     * OAEP source type - CKZ_DATA_SPECIFIED means use pSourceData.
     */
    public static final long SOURCE_DATA_SPECIFIED = 0x00000001L;

    /**
     * Hash algorithm used in OAEP encoding (CKM_* value).
     */
    public NativeLong hashAlg;

    /**
     * Mask generation function to use (CKG_MGF1_* value).
     */
    public NativeLong mgf;

    /**
     * Source of encoding parameter (usually CKZ_DATA_SPECIFIED).
     */
    public NativeLong source;

    /**
     * Pointer to encoding parameter (label) data. Can be null.
     */
    public Pointer pSourceData;

    /**
     * Length of encoding parameter in bytes.
     */
    public NativeLong ulSourceDataLen;

    public RsaPkcsOaepParams() {
        super();
    }

    /**
     * Creates RSA-OAEP parameters with specified hash algorithm.
     *
     * @param hashAlg the hash algorithm (CKM_SHA256, CKM_SHA384, etc.)
     * @param mgf     the mask generation function (MGF1_SHA256, etc.)
     */
    public RsaPkcsOaepParams(long hashAlg, long mgf) {
        super();
        this.hashAlg = new NativeLong(hashAlg);
        this.mgf = new NativeLong(mgf);
        this.source = new NativeLong(SOURCE_DATA_SPECIFIED);
        this.pSourceData = null;
        this.ulSourceDataLen = new NativeLong(0);
    }

    /**
     * Creates RSA-OAEP parameters for SHA-256.
     * Uses MGF1-SHA256.
     */
    public static RsaPkcsOaepParams sha256() {
        return new RsaPkcsOaepParams(MechanismType.SHA256, MGF1_SHA256);
    }

    /**
     * Creates RSA-OAEP parameters for SHA-384.
     * Uses MGF1-SHA384.
     */
    public static RsaPkcsOaepParams sha384() {
        return new RsaPkcsOaepParams(MechanismType.SHA384, MGF1_SHA384);
    }

    /**
     * Creates RSA-OAEP parameters for SHA-512.
     * Uses MGF1-SHA512.
     */
    public static RsaPkcsOaepParams sha512() {
        return new RsaPkcsOaepParams(MechanismType.SHA512, MGF1_SHA512);
    }

    /**
     * Creates RSA-OAEP parameters for SHA-1.
     * Uses MGF1-SHA1.
     */
    public static RsaPkcsOaepParams sha1() {
        return new RsaPkcsOaepParams(MechanismType.SHA_1, MGF1_SHA1);
    }

    /**
     * Creates RSA-OAEP parameters for SHA-224.
     * Uses MGF1-SHA224.
     */
    public static RsaPkcsOaepParams sha224() {
        return new RsaPkcsOaepParams(MechanismType.SHA224, MGF1_SHA224);
    }

    /**
     * Creates RSA-OAEP parameters as raw memory block.
     * This is more reliable for passing to native code.
     *
     * CK_RSA_PKCS_OAEP_PARAMS structure layout on 64-bit Windows:
     * - hashAlg: CK_MECHANISM_TYPE (4 bytes) - offset 0
     * - mgf: CK_RSA_PKCS_MGF_TYPE (4 bytes) - offset 4
     * - source: CK_RSA_PKCS_OAEP_SOURCE_TYPE (4 bytes) - offset 8
     * - padding: 4 bytes for 8-byte pointer alignment - offset 12
     * - pSourceData: CK_VOID_PTR (8 bytes) - offset 16
     * - ulSourceDataLen: CK_ULONG (4 bytes) - offset 24
     * - padding: 4 bytes for struct alignment - offset 28
     * Total: 32 bytes on 64-bit Windows
     */
    public static Pointer createAsMemory(long hashAlg, long mgf) {
        int nativeSize = NativeLong.SIZE;
        int pointerSize = Native.POINTER_SIZE;

        int hashAlgOffset = 0;
        int mgfOffset = nativeSize;
        int sourceOffset = 2 * nativeSize;
        int pSourceDataOffset;
        int ulSourceDataLenOffset;

        if (pointerSize > nativeSize) {
            int afterSource = sourceOffset + nativeSize;
            pSourceDataOffset = ((afterSource + pointerSize - 1) / pointerSize) * pointerSize;
        } else {
            pSourceDataOffset = sourceOffset + nativeSize;
        }
        ulSourceDataLenOffset = pSourceDataOffset + pointerSize;

        int totalSize = ulSourceDataLenOffset + nativeSize;
        if (totalSize % pointerSize != 0) {
            totalSize = ((totalSize / pointerSize) + 1) * pointerSize;
        }

        Memory mem = new Memory(totalSize);
        mem.clear();

        mem.setNativeLong(hashAlgOffset, new NativeLong(hashAlg));
        mem.setNativeLong(mgfOffset, new NativeLong(mgf));
        mem.setNativeLong(sourceOffset, new NativeLong(SOURCE_DATA_SPECIFIED));
        mem.setPointer(pSourceDataOffset, null);
        mem.setNativeLong(ulSourceDataLenOffset, new NativeLong(0));

        return mem;
    }

    /**
     * Gets the size of the CK_RSA_PKCS_OAEP_PARAMS structure with proper alignment.
     */
    public static int getStructSize() {
        int nativeSize = NativeLong.SIZE;
        int pointerSize = Native.POINTER_SIZE;

        int sourceOffset = 2 * nativeSize;
        int pSourceDataOffset;

        if (pointerSize > nativeSize) {
            int afterSource = sourceOffset + nativeSize;
            pSourceDataOffset = ((afterSource + pointerSize - 1) / pointerSize) * pointerSize;
        } else {
            pSourceDataOffset = sourceOffset + nativeSize;
        }
        int ulSourceDataLenOffset = pSourceDataOffset + pointerSize;
        int totalSize = ulSourceDataLenOffset + nativeSize;

        if (totalSize % pointerSize != 0) {
            totalSize = ((totalSize / pointerSize) + 1) * pointerSize;
        }

        return totalSize;
    }

    public static class ByReference extends RsaPkcsOaepParams implements Structure.ByReference {}
    public static class ByValue extends RsaPkcsOaepParams implements Structure.ByValue {}
}
