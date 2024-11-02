package pl.mlodawski.security.pkcs11.model;

/**
 * Enum representing various device capabilities.
 *
 * The DeviceCapability enum includes the following capabilities:
 *
 * RANDOM_NUMBER_GENERATION - Indicates the device can generate random numbers.
 * WRITE_ENABLED - Indicates the device allows data to be written to it.
 * LOGIN_REQUIRED - Indicates that login is required to use the device.
 * KEY_RESTORATION_NOT_NEEDED - Indicates that key restoration is not needed for the device.
 * CLOCK_AVAILABLE - Indicates the device has an available clock.
 * PROTECTED_AUTHENTICATION_PATH - Indicates that a protected authentication path is available.
 * DUAL_CRYPTO_OPERATIONS - Indicates the device can perform dual cryptographic operations.
 */
public enum DeviceCapability {
    RANDOM_NUMBER_GENERATION,
    WRITE_ENABLED,
    LOGIN_REQUIRED,
    KEY_RESTORATION_NOT_NEEDED,
    CLOCK_AVAILABLE,
    PROTECTED_AUTHENTICATION_PATH,
    DUAL_CRYPTO_OPERATIONS
}
