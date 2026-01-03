package pl.mlodawski.security.pkcs11.jna.constants;

/**
 * PKCS#11 mechanism capability flags.
 * Based on OASIS PKCS#11 specification.
 */
public final class MechanismFlags {

    private MechanismFlags() {}

    public static final long HW = 0x00000001L;
    public static final long ENCRYPT = 0x00000100L;
    public static final long DECRYPT = 0x00000200L;
    public static final long DIGEST = 0x00000400L;
    public static final long SIGN = 0x00000800L;
    public static final long SIGN_RECOVER = 0x00001000L;
    public static final long VERIFY = 0x00002000L;
    public static final long VERIFY_RECOVER = 0x00004000L;
    public static final long GENERATE = 0x00008000L;
    public static final long GENERATE_KEY_PAIR = 0x00010000L;
    public static final long WRAP = 0x00020000L;
    public static final long UNWRAP = 0x00040000L;
    public static final long DERIVE = 0x00080000L;
    public static final long EC_F_P = 0x00100000L;
    public static final long EC_F_2M = 0x00200000L;
    public static final long EC_ECPARAMETERS = 0x00400000L;
    public static final long EC_OID = 0x00800000L;
    public static final long EC_UNCOMPRESS = 0x01000000L;
    public static final long EC_COMPRESS = 0x02000000L;

    /**
     * Checks if the given flags contain the specified flag.
     */
    public static boolean hasFlag(long flags, long flag) {
        return (flags & flag) != 0;
    }
}
