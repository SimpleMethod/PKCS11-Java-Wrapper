package pl.mlodawski.security.pkcs11.jna.structure;

import com.sun.jna.Memory;
import com.sun.jna.NativeLong;
import com.sun.jna.Pointer;
import com.sun.jna.Structure;
import pl.mlodawski.security.pkcs11.jna.constants.MechanismType;

/**
 * PKCS#11 CK_MECHANISM structure.
 * Specifies a particular mechanism and any parameters it requires.
 * Based on OASIS PKCS#11 specification.
 */
@Structure.FieldOrder({"mechanism", "pParameter", "ulParameterLen"})
public class Mechanism extends Structure {

    /**
     * The mechanism type (CKM_* value).
     */
    public NativeLong mechanism;

    /**
     * Pointer to mechanism-specific parameters.
     */
    public Pointer pParameter;

    /**
     * Length of the parameters in bytes.
     */
    public NativeLong ulParameterLen;

    /**
     * Reference to the parameter structure to prevent garbage collection.
     */
    private Structure paramsRef;

    /**
     * Reference to raw memory parameters to prevent garbage collection.
     */
    private Memory paramsMemory;

    public Mechanism() {
        super();
    }

    /**
     * Creates a mechanism with no parameters.
     */
    public Mechanism(long mechanismType) {
        super();
        this.mechanism = new NativeLong(mechanismType);
        this.pParameter = null;
        this.ulParameterLen = new NativeLong(0);
        this.write();
    }

    /**
     * Creates a mechanism with byte array parameters.
     */
    public Mechanism(long mechanismType, byte[] parameters) {
        super();
        this.mechanism = new NativeLong(mechanismType);
        if (parameters != null && parameters.length > 0) {
            this.pParameter = new com.sun.jna.Memory(parameters.length);
            this.pParameter.write(0, parameters, 0, parameters.length);
            this.ulParameterLen = new NativeLong(parameters.length);
        } else {
            this.pParameter = null;
            this.ulParameterLen = new NativeLong(0);
        }
        this.write();
    }

    /**
     * Returns the mechanism type value.
     */
    public long getMechanismType() {
        return mechanism != null ? mechanism.longValue() : 0;
    }

    /**
     * Returns the mechanism name.
     */
    public String getMechanismName() {
        return MechanismType.getName(getMechanismType());
    }

    /**
     * Creates a mechanism for RSA PKCS operations.
     */
    public static Mechanism createRsaPkcs() {
        return new Mechanism(MechanismType.RSA_PKCS);
    }

    /**
     * Creates a mechanism for SHA256 with RSA PKCS signing.
     */
    public static Mechanism createSha256RsaPkcs() {
        return new Mechanism(MechanismType.SHA256_RSA_PKCS);
    }

    /**
     * Creates a mechanism for SHA1 with RSA PKCS signing.
     */
    public static Mechanism createSha1RsaPkcs() {
        return new Mechanism(MechanismType.SHA1_RSA_PKCS);
    }

    /**
     * Creates a mechanism with a Structure as parameter.
     */
    public Mechanism(long mechanismType, Structure params) {
        super();
        this.mechanism = new NativeLong(mechanismType);
        if (params != null) {
            this.paramsRef = params;
            params.write();
            this.pParameter = params.getPointer();
            this.ulParameterLen = new NativeLong(params.size());
        } else {
            this.pParameter = null;
            this.ulParameterLen = new NativeLong(0);
        }
        this.write();
    }

    /**
     * Creates a mechanism with raw Memory as parameter.
     * This is more reliable for complex parameter structures.
     */
    public Mechanism(long mechanismType, Memory paramsMemory, int paramsSize) {
        super();
        this.mechanism = new NativeLong(mechanismType);
        if (paramsMemory != null) {
            this.paramsMemory = paramsMemory;
            this.pParameter = paramsMemory;
            this.ulParameterLen = new NativeLong(paramsSize);
        } else {
            this.pParameter = null;
            this.ulParameterLen = new NativeLong(0);
        }
        this.write();
    }

    /**
     * Creates a mechanism as raw memory block and returns it.
     * This is the most reliable way to pass mechanism to native code.
     *
     * CK_MECHANISM structure layout on 64-bit:
     * - mechanism: CK_MECHANISM_TYPE (NativeLong - 4 bytes on Windows, 8 on Linux)
     * - padding: (4 bytes on Windows to align pointer)
     * - pParameter: CK_VOID_PTR (8 bytes pointer)
     * - ulParameterLen: CK_ULONG (NativeLong - 4 bytes on Windows, 8 on Linux)
     */
    public static Memory createAsMemory(long mechanismType, Memory params, int paramsSize) {
        int nlSize = NativeLong.SIZE;
        int ptrSize = com.sun.jna.Native.POINTER_SIZE;

        int mechanismOffset = 0;
        int pParameterOffset;
        int ulParameterLenOffset;

        if (nlSize < ptrSize) {
            pParameterOffset = ptrSize;
        } else {
            pParameterOffset = nlSize;
        }
        ulParameterLenOffset = pParameterOffset + ptrSize;

        int totalSize = ulParameterLenOffset + nlSize;
        if (totalSize % ptrSize != 0) {
            totalSize = ((totalSize / ptrSize) + 1) * ptrSize;
        }

        Memory mem = new Memory(totalSize);
        mem.clear();

        mem.setNativeLong(mechanismOffset, new NativeLong(mechanismType));
        if (params != null) {
            mem.setPointer(pParameterOffset, params);
            mem.setNativeLong(ulParameterLenOffset, new NativeLong(paramsSize));
        } else {
            mem.setPointer(pParameterOffset, null);
            mem.setNativeLong(ulParameterLenOffset, new NativeLong(0));
        }

        return mem;
    }

    /**
     * Creates RSA-PSS SHA-256 mechanism as raw memory.
     */
    public static Memory createSha256RsaPssAsMemory() {
        Memory params = (Memory) RsaPkcsPssParams.createAsMemory(
                MechanismType.SHA256, RsaPkcsPssParams.MGF1_SHA256, 32);
        return createAsMemory(MechanismType.SHA256_RSA_PKCS_PSS, params, RsaPkcsPssParams.getStructSize());
    }

    /**
     * Creates RSA-PSS SHA-384 mechanism as raw memory.
     */
    public static Memory createSha384RsaPssAsMemory() {
        Memory params = (Memory) RsaPkcsPssParams.createAsMemory(
                MechanismType.SHA384, RsaPkcsPssParams.MGF1_SHA384, 48);
        return createAsMemory(MechanismType.SHA384_RSA_PKCS_PSS, params, RsaPkcsPssParams.getStructSize());
    }

    /**
     * Creates RSA-PSS SHA-512 mechanism as raw memory.
     */
    public static Memory createSha512RsaPssAsMemory() {
        Memory params = (Memory) RsaPkcsPssParams.createAsMemory(
                MechanismType.SHA512, RsaPkcsPssParams.MGF1_SHA512, 64);
        return createAsMemory(MechanismType.SHA512_RSA_PKCS_PSS, params, RsaPkcsPssParams.getStructSize());
    }

    /**
     * Creates RSA-PSS SHA-1 mechanism as raw memory.
     */
    public static Memory createSha1RsaPssAsMemory() {
        Memory params = (Memory) RsaPkcsPssParams.createAsMemory(
                MechanismType.SHA_1, RsaPkcsPssParams.MGF1_SHA1, 20);
        return createAsMemory(MechanismType.SHA1_RSA_PKCS_PSS, params, RsaPkcsPssParams.getStructSize());
    }

    /**
     * Creates RSA-PSS SHA-224 mechanism as raw memory.
     */
    public static Memory createSha224RsaPssAsMemory() {
        Memory params = (Memory) RsaPkcsPssParams.createAsMemory(
                MechanismType.SHA224, RsaPkcsPssParams.MGF1_SHA224, 28);
        return createAsMemory(MechanismType.SHA224_RSA_PKCS_PSS, params, RsaPkcsPssParams.getStructSize());
    }

    /**
     * Creates RSA-OAEP SHA-1 mechanism as raw memory.
     */
    public static Memory createRsaOaepSha1AsMemory() {
        Memory params = (Memory) RsaPkcsOaepParams.createAsMemory(
                MechanismType.SHA_1, RsaPkcsOaepParams.MGF1_SHA1);
        return createAsMemory(MechanismType.RSA_PKCS_OAEP, params, RsaPkcsOaepParams.getStructSize());
    }

    /**
     * Creates RSA-OAEP SHA-256 mechanism as raw memory.
     */
    public static Memory createRsaOaepSha256AsMemory() {
        Memory params = (Memory) RsaPkcsOaepParams.createAsMemory(
                MechanismType.SHA256, RsaPkcsOaepParams.MGF1_SHA256);
        return createAsMemory(MechanismType.RSA_PKCS_OAEP, params, RsaPkcsOaepParams.getStructSize());
    }

    /**
     * Creates RSA-OAEP SHA-384 mechanism as raw memory.
     */
    public static Memory createRsaOaepSha384AsMemory() {
        Memory params = (Memory) RsaPkcsOaepParams.createAsMemory(
                MechanismType.SHA384, RsaPkcsOaepParams.MGF1_SHA384);
        return createAsMemory(MechanismType.RSA_PKCS_OAEP, params, RsaPkcsOaepParams.getStructSize());
    }

    /**
     * Creates RSA-OAEP SHA-512 mechanism as raw memory.
     */
    public static Memory createRsaOaepSha512AsMemory() {
        Memory params = (Memory) RsaPkcsOaepParams.createAsMemory(
                MechanismType.SHA512, RsaPkcsOaepParams.MGF1_SHA512);
        return createAsMemory(MechanismType.RSA_PKCS_OAEP, params, RsaPkcsOaepParams.getStructSize());
    }

    /**
     * Creates a mechanism for RSA-PSS with SHA-256.
     */
    public static Mechanism createSha256RsaPss() {
        Memory params = (Memory) RsaPkcsPssParams.createAsMemory(
                MechanismType.SHA256, RsaPkcsPssParams.MGF1_SHA256, 32);
        return new Mechanism(MechanismType.SHA256_RSA_PKCS_PSS, params, RsaPkcsPssParams.getStructSize());
    }

    /**
     * Creates a mechanism for RSA-PSS with SHA-384.
     */
    public static Mechanism createSha384RsaPss() {
        Memory params = (Memory) RsaPkcsPssParams.createAsMemory(
                MechanismType.SHA384, RsaPkcsPssParams.MGF1_SHA384, 48);
        return new Mechanism(MechanismType.SHA384_RSA_PKCS_PSS, params, RsaPkcsPssParams.getStructSize());
    }

    /**
     * Creates a mechanism for RSA-PSS with SHA-512.
     */
    public static Mechanism createSha512RsaPss() {
        Memory params = (Memory) RsaPkcsPssParams.createAsMemory(
                MechanismType.SHA512, RsaPkcsPssParams.MGF1_SHA512, 64);
        return new Mechanism(MechanismType.SHA512_RSA_PKCS_PSS, params, RsaPkcsPssParams.getStructSize());
    }

    /**
     * Creates a mechanism for RSA-PSS with SHA-1.
     */
    public static Mechanism createSha1RsaPss() {
        Memory params = (Memory) RsaPkcsPssParams.createAsMemory(
                MechanismType.SHA_1, RsaPkcsPssParams.MGF1_SHA1, 20);
        return new Mechanism(MechanismType.SHA1_RSA_PKCS_PSS, params, RsaPkcsPssParams.getStructSize());
    }

    /**
     * Creates a mechanism for RSA-PSS with SHA-224.
     */
    public static Mechanism createSha224RsaPss() {
        Memory params = (Memory) RsaPkcsPssParams.createAsMemory(
                MechanismType.SHA224, RsaPkcsPssParams.MGF1_SHA224, 28);
        return new Mechanism(MechanismType.SHA224_RSA_PKCS_PSS, params, RsaPkcsPssParams.getStructSize());
    }

    /**
     * Creates a mechanism for RSA-OAEP with SHA-1 (default, most compatible).
     */
    public static Mechanism createRsaOaepSha1() {
        Memory params = (Memory) RsaPkcsOaepParams.createAsMemory(
                MechanismType.SHA_1, RsaPkcsOaepParams.MGF1_SHA1);
        return new Mechanism(MechanismType.RSA_PKCS_OAEP, params, RsaPkcsOaepParams.getStructSize());
    }

    /**
     * Creates a mechanism for RSA-OAEP with SHA-256.
     */
    public static Mechanism createRsaOaepSha256() {
        Memory params = (Memory) RsaPkcsOaepParams.createAsMemory(
                MechanismType.SHA256, RsaPkcsOaepParams.MGF1_SHA256);
        return new Mechanism(MechanismType.RSA_PKCS_OAEP, params, RsaPkcsOaepParams.getStructSize());
    }

    /**
     * Creates a mechanism for RSA-OAEP with SHA-384.
     */
    public static Mechanism createRsaOaepSha384() {
        Memory params = (Memory) RsaPkcsOaepParams.createAsMemory(
                MechanismType.SHA384, RsaPkcsOaepParams.MGF1_SHA384);
        return new Mechanism(MechanismType.RSA_PKCS_OAEP, params, RsaPkcsOaepParams.getStructSize());
    }

    /**
     * Creates a mechanism for RSA-OAEP with SHA-512.
     */
    public static Mechanism createRsaOaepSha512() {
        Memory params = (Memory) RsaPkcsOaepParams.createAsMemory(
                MechanismType.SHA512, RsaPkcsOaepParams.MGF1_SHA512);
        return new Mechanism(MechanismType.RSA_PKCS_OAEP, params, RsaPkcsOaepParams.getStructSize());
    }

    /**
     * Creates a mechanism for ECDH key derivation with NULL KDF.
     *
     * @param peerPublicKey peer's EC public key (EC point in uncompressed format)
     */
    public static Mechanism createEcdh1Derive(byte[] peerPublicKey) {
        return new Mechanism(MechanismType.ECDH1_DERIVE, Ecdh1DeriveParams.withNullKdf(peerPublicKey));
    }

    /**
     * Creates a mechanism for ECDH key derivation with SHA-256 KDF.
     *
     * @param peerPublicKey peer's EC public key (EC point in uncompressed format)
     */
    public static Mechanism createEcdh1DeriveSha256(byte[] peerPublicKey) {
        return new Mechanism(MechanismType.ECDH1_DERIVE, Ecdh1DeriveParams.withSha256Kdf(peerPublicKey));
    }

    /**
     * Creates a mechanism for ECDH cofactor derivation.
     *
     * @param peerPublicKey peer's EC public key (EC point in uncompressed format)
     */
    public static Mechanism createEcdh1CofactorDerive(byte[] peerPublicKey) {
        return new Mechanism(MechanismType.ECDH1_COFACTOR_DERIVE, Ecdh1DeriveParams.withNullKdf(peerPublicKey));
    }

    public static class ByReference extends Mechanism implements Structure.ByReference {}
    public static class ByValue extends Mechanism implements Structure.ByValue {}
}
