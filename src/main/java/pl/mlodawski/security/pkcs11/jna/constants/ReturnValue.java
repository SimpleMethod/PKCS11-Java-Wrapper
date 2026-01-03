package pl.mlodawski.security.pkcs11.jna.constants;

import com.sun.jna.NativeLong;

/**
 * PKCS#11 return values (CKR_*).
 * Based on OASIS PKCS#11 specification.
 */
public final class ReturnValue {

    private ReturnValue() {}

    public static final long OK = 0x00000000L;
    public static final long CANCEL = 0x00000001L;
    public static final long HOST_MEMORY = 0x00000002L;
    public static final long SLOT_ID_INVALID = 0x00000003L;
    public static final long GENERAL_ERROR = 0x00000005L;
    public static final long FUNCTION_FAILED = 0x00000006L;
    public static final long ARGUMENTS_BAD = 0x00000007L;
    public static final long NO_EVENT = 0x00000008L;
    public static final long NEED_TO_CREATE_THREADS = 0x00000009L;
    public static final long CANT_LOCK = 0x0000000AL;

    public static final long ATTRIBUTE_READ_ONLY = 0x00000010L;
    public static final long ATTRIBUTE_SENSITIVE = 0x00000011L;
    public static final long ATTRIBUTE_TYPE_INVALID = 0x00000012L;
    public static final long ATTRIBUTE_VALUE_INVALID = 0x00000013L;

    public static final long ACTION_PROHIBITED = 0x0000001BL;

    public static final long DATA_INVALID = 0x00000020L;
    public static final long DATA_LEN_RANGE = 0x00000021L;

    public static final long DEVICE_ERROR = 0x00000030L;
    public static final long DEVICE_MEMORY = 0x00000031L;
    public static final long DEVICE_REMOVED = 0x00000032L;

    public static final long ENCRYPTED_DATA_INVALID = 0x00000040L;
    public static final long ENCRYPTED_DATA_LEN_RANGE = 0x00000041L;

    public static final long FUNCTION_CANCELED = 0x00000050L;
    public static final long FUNCTION_NOT_PARALLEL = 0x00000051L;
    public static final long FUNCTION_NOT_SUPPORTED = 0x00000054L;

    public static final long KEY_HANDLE_INVALID = 0x00000060L;
    public static final long KEY_SIZE_RANGE = 0x00000062L;
    public static final long KEY_TYPE_INCONSISTENT = 0x00000063L;
    public static final long KEY_NOT_NEEDED = 0x00000064L;
    public static final long KEY_CHANGED = 0x00000065L;
    public static final long KEY_NEEDED = 0x00000066L;
    public static final long KEY_INDIGESTIBLE = 0x00000067L;
    public static final long KEY_FUNCTION_NOT_PERMITTED = 0x00000068L;
    public static final long KEY_NOT_WRAPPABLE = 0x00000069L;
    public static final long KEY_UNEXTRACTABLE = 0x0000006AL;

    public static final long MECHANISM_INVALID = 0x00000070L;
    public static final long MECHANISM_PARAM_INVALID = 0x00000071L;

    public static final long OBJECT_HANDLE_INVALID = 0x00000082L;

    public static final long OPERATION_ACTIVE = 0x00000090L;
    public static final long OPERATION_NOT_INITIALIZED = 0x00000091L;

    public static final long PIN_INCORRECT = 0x000000A0L;
    public static final long PIN_INVALID = 0x000000A1L;
    public static final long PIN_LEN_RANGE = 0x000000A2L;
    public static final long PIN_EXPIRED = 0x000000A3L;
    public static final long PIN_LOCKED = 0x000000A4L;

    public static final long SESSION_CLOSED = 0x000000B0L;
    public static final long SESSION_COUNT = 0x000000B1L;
    public static final long SESSION_HANDLE_INVALID = 0x000000B3L;
    public static final long SESSION_PARALLEL_NOT_SUPPORTED = 0x000000B4L;
    public static final long SESSION_READ_ONLY = 0x000000B5L;
    public static final long SESSION_EXISTS = 0x000000B6L;
    public static final long SESSION_READ_ONLY_EXISTS = 0x000000B7L;
    public static final long SESSION_READ_WRITE_SO_EXISTS = 0x000000B8L;

    public static final long SIGNATURE_INVALID = 0x000000C0L;
    public static final long SIGNATURE_LEN_RANGE = 0x000000C1L;

    public static final long TEMPLATE_INCOMPLETE = 0x000000D0L;
    public static final long TEMPLATE_INCONSISTENT = 0x000000D1L;

    public static final long TOKEN_NOT_PRESENT = 0x000000E0L;
    public static final long TOKEN_NOT_RECOGNIZED = 0x000000E1L;
    public static final long TOKEN_WRITE_PROTECTED = 0x000000E2L;

    public static final long UNWRAPPING_KEY_HANDLE_INVALID = 0x000000F0L;
    public static final long UNWRAPPING_KEY_SIZE_RANGE = 0x000000F1L;
    public static final long UNWRAPPING_KEY_TYPE_INCONSISTENT = 0x000000F2L;

    public static final long USER_ALREADY_LOGGED_IN = 0x00000100L;
    public static final long USER_NOT_LOGGED_IN = 0x00000101L;
    public static final long USER_PIN_NOT_INITIALIZED = 0x00000102L;
    public static final long USER_TYPE_INVALID = 0x00000103L;
    public static final long USER_ANOTHER_ALREADY_LOGGED_IN = 0x00000104L;
    public static final long USER_TOO_MANY_TYPES = 0x00000105L;

    public static final long WRAPPED_KEY_INVALID = 0x00000110L;
    public static final long WRAPPED_KEY_LEN_RANGE = 0x00000112L;
    public static final long WRAPPING_KEY_HANDLE_INVALID = 0x00000113L;
    public static final long WRAPPING_KEY_SIZE_RANGE = 0x00000114L;
    public static final long WRAPPING_KEY_TYPE_INCONSISTENT = 0x00000115L;

    public static final long RANDOM_SEED_NOT_SUPPORTED = 0x00000120L;
    public static final long RANDOM_NO_RNG = 0x00000121L;

    public static final long DOMAIN_PARAMS_INVALID = 0x00000130L;

    public static final long CURVE_NOT_SUPPORTED = 0x00000140L;

    public static final long BUFFER_TOO_SMALL = 0x00000150L;
    public static final long SAVED_STATE_INVALID = 0x00000160L;
    public static final long INFORMATION_SENSITIVE = 0x00000170L;
    public static final long STATE_UNSAVEABLE = 0x00000180L;

    public static final long CRYPTOKI_NOT_INITIALIZED = 0x00000190L;
    public static final long CRYPTOKI_ALREADY_INITIALIZED = 0x00000191L;

    public static final long MUTEX_BAD = 0x000001A0L;
    public static final long MUTEX_NOT_LOCKED = 0x000001A1L;

    public static final long VENDOR_DEFINED = 0x80000000L;

    /**
     * Checks if the given return value indicates success.
     */
    public static boolean isSuccess(NativeLong rv) {
        return rv != null && rv.longValue() == OK;
    }

    /**
     * Checks if the given return value indicates success.
     */
    public static boolean isSuccess(long rv) {
        return rv == OK;
    }
}
