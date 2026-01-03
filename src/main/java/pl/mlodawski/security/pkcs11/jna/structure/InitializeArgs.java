package pl.mlodawski.security.pkcs11.jna.structure;

import com.sun.jna.NativeLong;
import com.sun.jna.Pointer;
import com.sun.jna.Structure;

/**
 * PKCS#11 CK_C_INITIALIZE_ARGS structure.
 * Arguments for C_Initialize function.
 * Based on OASIS PKCS#11 specification.
 */
@Structure.FieldOrder({"CreateMutex", "DestroyMutex", "LockMutex", "UnlockMutex", "flags", "pReserved"})
public class InitializeArgs extends Structure {

    /**
     * Flag: library can create its own threads for callbacks.
     */
    public static final long FLAG_LIBRARY_CANT_CREATE_OS_THREADS = 0x00000001L;

    /**
     * Flag: application is providing locking primitives.
     */
    public static final long FLAG_OS_LOCKING_OK = 0x00000002L;

    /**
     * Pointer to a function for creating mutexes (NULL for default).
     */
    public Pointer CreateMutex;

    /**
     * Pointer to a function for destroying mutexes (NULL for default).
     */
    public Pointer DestroyMutex;

    /**
     * Pointer to a function for locking mutexes (NULL for default).
     */
    public Pointer LockMutex;

    /**
     * Pointer to a function for unlocking mutexes (NULL for default).
     */
    public Pointer UnlockMutex;

    /**
     * Bit flags specifying options.
     */
    public NativeLong flags;

    /**
     * Reserved for future use; must be NULL.
     */
    public Pointer pReserved;

    public InitializeArgs() {
        super();
    }

    /**
     * Creates default initialization arguments with OS locking enabled.
     */
    public static InitializeArgs createDefault() {
        InitializeArgs args = new InitializeArgs();
        args.flags = new NativeLong(FLAG_OS_LOCKING_OK);
        return args;
    }

    public static class ByReference extends InitializeArgs implements Structure.ByReference {}
    public static class ByValue extends InitializeArgs implements Structure.ByValue {}
}
