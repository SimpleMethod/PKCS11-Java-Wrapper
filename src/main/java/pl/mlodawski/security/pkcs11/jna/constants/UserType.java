package pl.mlodawski.security.pkcs11.jna.constants;

/**
 * PKCS#11 user types (CKU_*).
 * Based on OASIS PKCS#11 specification.
 */
public final class UserType {

    private UserType() {}

    /**
     * Security Officer user.
     */
    public static final long SO = 0x00000000L;

    /**
     * Normal user.
     */
    public static final long USER = 0x00000001L;

    /**
     * Context-specific user (for re-authentication).
     */
    public static final long CONTEXT_SPECIFIC = 0x00000002L;
}
