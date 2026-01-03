package pl.mlodawski.security.pkcs11.jna.structure;

import com.sun.jna.Memory;
import com.sun.jna.NativeLong;
import com.sun.jna.Native;
import pl.mlodawski.security.pkcs11.jna.constants.MechanismType;

/**
 * Holds mechanism and its parameters in raw memory.
 * This class ensures that both the mechanism and parameter memory
 * are kept alive during the native call to prevent garbage collection.
 */
public class MechanismHolder {

    /** Raw memory containing the CK_MECHANISM structure */
    private final Memory mechanismMemory;

    /** Raw memory containing the mechanism parameters (e.g., PSS or OAEP params) */
    private final Memory paramsMemory;

    private MechanismHolder(Memory mechanismMemory, Memory paramsMemory) {
        this.mechanismMemory = mechanismMemory;
        this.paramsMemory = paramsMemory;
    }

    /**
     * Returns the pointer to the mechanism structure for passing to native code.
     */
    public Memory getMechanismPointer() {
        return mechanismMemory;
    }

    /**
     * Dumps the mechanism memory contents for debugging.
     */
    public String dumpMechanismMemory() {
        StringBuilder sb = new StringBuilder();
        sb.append("Mechanism memory dump (").append(mechanismMemory.size()).append(" bytes):\n");
        for (int i = 0; i < mechanismMemory.size(); i++) {
            sb.append(String.format("%02X ", mechanismMemory.getByte(i)));
            if ((i + 1) % 8 == 0) sb.append("\n");
        }
        if (paramsMemory != null) {
            sb.append("\nParams memory dump (").append(paramsMemory.size()).append(" bytes):\n");
            for (int i = 0; i < paramsMemory.size(); i++) {
                sb.append(String.format("%02X ", paramsMemory.getByte(i)));
                if ((i + 1) % 8 == 0) sb.append("\n");
            }
        }
        return sb.toString();
    }

    /**
     * Creates a mechanism holder with the given mechanism type and no parameters.
     */
    public static MechanismHolder create(long mechanismType) {
        Memory mechanismMem = createMechanismMemory(mechanismType, null, 0);
        return new MechanismHolder(mechanismMem, null);
    }

    /**
     * Creates a mechanism holder with the given mechanism type and parameters.
     */
    public static MechanismHolder create(long mechanismType, Memory params, int paramsSize) {
        Memory mechanismMem = createMechanismMemory(mechanismType, params, paramsSize);
        return new MechanismHolder(mechanismMem, params);
    }

    /**
     * Creates the CK_MECHANISM structure in raw memory.
     *
     * CK_MECHANISM structure layout on 64-bit:
     * - mechanism: CK_MECHANISM_TYPE (NativeLong - 4 bytes on Windows, 8 on Linux)
     * - padding: (4 bytes on Windows to align pointer)
     * - pParameter: CK_VOID_PTR (8 bytes pointer)
     * - ulParameterLen: CK_ULONG (NativeLong - 4 bytes on Windows, 8 on Linux)
     */
    private static Memory createMechanismMemory(long mechanismType, Memory params, int paramsSize) {
        int nlSize = NativeLong.SIZE;
        int ptrSize = Native.POINTER_SIZE;

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
     * Creates RSA-PSS SHA-1 mechanism holder.
     */
    public static MechanismHolder createSha1RsaPss() {
        Memory params = (Memory) RsaPkcsPssParams.createAsMemory(
                MechanismType.SHA_1, RsaPkcsPssParams.MGF1_SHA1, 20);
        return create(MechanismType.SHA1_RSA_PKCS_PSS, params, RsaPkcsPssParams.getStructSize());
    }

    /**
     * Creates RSA-PSS SHA-224 mechanism holder.
     */
    public static MechanismHolder createSha224RsaPss() {
        Memory params = (Memory) RsaPkcsPssParams.createAsMemory(
                MechanismType.SHA224, RsaPkcsPssParams.MGF1_SHA224, 28);
        return create(MechanismType.SHA224_RSA_PKCS_PSS, params, RsaPkcsPssParams.getStructSize());
    }

    /**
     * Creates RSA-PSS SHA-256 mechanism holder.
     */
    public static MechanismHolder createSha256RsaPss() {
        Memory params = (Memory) RsaPkcsPssParams.createAsMemory(
                MechanismType.SHA256, RsaPkcsPssParams.MGF1_SHA256, 32);
        return create(MechanismType.SHA256_RSA_PKCS_PSS, params, RsaPkcsPssParams.getStructSize());
    }

    /**
     * Creates RSA-PSS SHA-384 mechanism holder.
     */
    public static MechanismHolder createSha384RsaPss() {
        Memory params = (Memory) RsaPkcsPssParams.createAsMemory(
                MechanismType.SHA384, RsaPkcsPssParams.MGF1_SHA384, 48);
        return create(MechanismType.SHA384_RSA_PKCS_PSS, params, RsaPkcsPssParams.getStructSize());
    }

    /**
     * Creates RSA-PSS SHA-512 mechanism holder.
     */
    public static MechanismHolder createSha512RsaPss() {
        Memory params = (Memory) RsaPkcsPssParams.createAsMemory(
                MechanismType.SHA512, RsaPkcsPssParams.MGF1_SHA512, 64);
        return create(MechanismType.SHA512_RSA_PKCS_PSS, params, RsaPkcsPssParams.getStructSize());
    }

    /**
     * Creates RSA-OAEP SHA-1 mechanism holder.
     */
    public static MechanismHolder createRsaOaepSha1() {
        Memory params = (Memory) RsaPkcsOaepParams.createAsMemory(
                MechanismType.SHA_1, RsaPkcsOaepParams.MGF1_SHA1);
        return create(MechanismType.RSA_PKCS_OAEP, params, RsaPkcsOaepParams.getStructSize());
    }

    /**
     * Creates RSA-OAEP SHA-256 mechanism holder.
     */
    public static MechanismHolder createRsaOaepSha256() {
        Memory params = (Memory) RsaPkcsOaepParams.createAsMemory(
                MechanismType.SHA256, RsaPkcsOaepParams.MGF1_SHA256);
        return create(MechanismType.RSA_PKCS_OAEP, params, RsaPkcsOaepParams.getStructSize());
    }

    /**
     * Creates RSA-OAEP SHA-384 mechanism holder.
     */
    public static MechanismHolder createRsaOaepSha384() {
        Memory params = (Memory) RsaPkcsOaepParams.createAsMemory(
                MechanismType.SHA384, RsaPkcsOaepParams.MGF1_SHA384);
        return create(MechanismType.RSA_PKCS_OAEP, params, RsaPkcsOaepParams.getStructSize());
    }

    /**
     * Creates RSA-OAEP SHA-512 mechanism holder.
     */
    public static MechanismHolder createRsaOaepSha512() {
        Memory params = (Memory) RsaPkcsOaepParams.createAsMemory(
                MechanismType.SHA512, RsaPkcsOaepParams.MGF1_SHA512);
        return create(MechanismType.RSA_PKCS_OAEP, params, RsaPkcsOaepParams.getStructSize());
    }
}
