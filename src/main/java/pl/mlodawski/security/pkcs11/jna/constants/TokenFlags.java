package pl.mlodawski.security.pkcs11.jna.constants;

/**
 * PKCS#11 token and slot flags.
 * Based on OASIS PKCS#11 specification.
 */
public final class TokenFlags {

    private TokenFlags() {}

    // Slot flags
    public static final long TOKEN_PRESENT = 0x00000001L;
    public static final long REMOVABLE_DEVICE = 0x00000002L;
    public static final long HW_SLOT = 0x00000004L;

    // Token flags
    public static final long RNG = 0x00000001L;
    public static final long WRITE_PROTECTED = 0x00000002L;
    public static final long LOGIN_REQUIRED = 0x00000004L;
    public static final long USER_PIN_INITIALIZED = 0x00000008L;
    public static final long RESTORE_KEY_NOT_NEEDED = 0x00000020L;
    public static final long CLOCK_ON_TOKEN = 0x00000040L;
    public static final long PROTECTED_AUTHENTICATION_PATH = 0x00000100L;
    public static final long DUAL_CRYPTO_OPERATIONS = 0x00000200L;
    public static final long TOKEN_INITIALIZED = 0x00000400L;
    public static final long SECONDARY_AUTHENTICATION = 0x00000800L;
    public static final long USER_PIN_COUNT_LOW = 0x00010000L;
    public static final long USER_PIN_FINAL_TRY = 0x00020000L;
    public static final long USER_PIN_LOCKED = 0x00040000L;
    public static final long USER_PIN_TO_BE_CHANGED = 0x00080000L;
    public static final long SO_PIN_COUNT_LOW = 0x00100000L;
    public static final long SO_PIN_FINAL_TRY = 0x00200000L;
    public static final long SO_PIN_LOCKED = 0x00400000L;
    public static final long SO_PIN_TO_BE_CHANGED = 0x00800000L;
    public static final long ERROR_STATE = 0x01000000L;

    /**
     * Checks if the given flags contain the specified flag.
     */
    public static boolean hasFlag(long flags, long flag) {
        return (flags & flag) != 0;
    }
}
