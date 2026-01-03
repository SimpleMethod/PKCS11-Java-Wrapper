package pl.mlodawski.security.pkcs11.jna.constants;

/**
 * PKCS#11 object classes (CKO_*).
 * Based on OASIS PKCS#11 specification.
 */
public final class ObjectClass {

    private ObjectClass() {}

    public static final long DATA = 0x00000000L;
    public static final long CERTIFICATE = 0x00000001L;
    public static final long PUBLIC_KEY = 0x00000002L;
    public static final long PRIVATE_KEY = 0x00000003L;
    public static final long SECRET_KEY = 0x00000004L;
    public static final long HW_FEATURE = 0x00000005L;
    public static final long DOMAIN_PARAMETERS = 0x00000006L;
    public static final long MECHANISM = 0x00000007L;
    public static final long OTP_KEY = 0x00000008L;
    public static final long VENDOR_DEFINED = 0x80000000L;
}
