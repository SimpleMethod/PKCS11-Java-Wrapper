package pl.mlodawski.security.pkcs11.jna.constants;

/**
 * PKCS#11 session flags.
 * Based on OASIS PKCS#11 specification.
 */
public final class SessionFlags {

    private SessionFlags() {}

    /**
     * Session is read/write (not read-only).
     */
    public static final long RW_SESSION = 0x00000002L;

    /**
     * No parallel sessions (legacy flag, must always be set).
     */
    public static final long SERIAL_SESSION = 0x00000004L;
}
