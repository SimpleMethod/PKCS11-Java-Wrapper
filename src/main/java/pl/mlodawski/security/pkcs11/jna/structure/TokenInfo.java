package pl.mlodawski.security.pkcs11.jna.structure;

import com.sun.jna.NativeLong;
import com.sun.jna.Structure;
import pl.mlodawski.security.pkcs11.jna.constants.TokenFlags;

import java.nio.charset.StandardCharsets;

/**
 * PKCS#11 CK_TOKEN_INFO structure.
 * Provides information about a token.
 * Based on OASIS PKCS#11 specification.
 */
@Structure.FieldOrder({
    "label", "manufacturerID", "model", "serialNumber",
    "flags", "ulMaxSessionCount", "ulSessionCount",
    "ulMaxRwSessionCount", "ulRwSessionCount",
    "ulMaxPinLen", "ulMinPinLen", "ulTotalPublicMemory",
    "ulFreePublicMemory", "ulTotalPrivateMemory",
    "ulFreePrivateMemory", "hardwareVersion", "firmwareVersion", "utcTime"
})
public class TokenInfo extends Structure {

    /**
     * Token label (32 bytes, blank padded).
     */
    public byte[] label = new byte[32];

    /**
     * Manufacturer ID (32 bytes, blank padded).
     */
    public byte[] manufacturerID = new byte[32];

    /**
     * Token model (16 bytes, blank padded).
     */
    public byte[] model = new byte[16];

    /**
     * Serial number (16 bytes, blank padded).
     */
    public byte[] serialNumber = new byte[16];

    /**
     * Bit flags indicating token capabilities.
     */
    public NativeLong flags;

    /**
     * Maximum number of sessions.
     */
    public NativeLong ulMaxSessionCount;

    /**
     * Current number of sessions.
     */
    public NativeLong ulSessionCount;

    /**
     * Maximum number of read/write sessions.
     */
    public NativeLong ulMaxRwSessionCount;

    /**
     * Current number of read/write sessions.
     */
    public NativeLong ulRwSessionCount;

    /**
     * Maximum PIN length.
     */
    public NativeLong ulMaxPinLen;

    /**
     * Minimum PIN length.
     */
    public NativeLong ulMinPinLen;

    /**
     * Total public memory.
     */
    public NativeLong ulTotalPublicMemory;

    /**
     * Free public memory.
     */
    public NativeLong ulFreePublicMemory;

    /**
     * Total private memory.
     */
    public NativeLong ulTotalPrivateMemory;

    /**
     * Free private memory.
     */
    public NativeLong ulFreePrivateMemory;

    /**
     * Hardware version.
     */
    public Version hardwareVersion;

    /**
     * Firmware version.
     */
    public Version firmwareVersion;

    /**
     * UTC time (16 bytes, format: YYYYMMDDhhmmssxx).
     */
    public byte[] utcTime = new byte[16];

    public TokenInfo() {
        super();
    }

    /**
     * Returns the token label as a trimmed string.
     */
    public String getLabel() {
        return new String(label, StandardCharsets.UTF_8).trim();
    }

    /**
     * Returns the manufacturer ID as a trimmed string.
     */
    public String getManufacturerID() {
        return new String(manufacturerID, StandardCharsets.UTF_8).trim();
    }

    /**
     * Returns the model as a trimmed string.
     */
    public String getModel() {
        return new String(model, StandardCharsets.UTF_8).trim();
    }

    /**
     * Returns the serial number as a trimmed string.
     */
    public String getSerialNumber() {
        return new String(serialNumber, StandardCharsets.UTF_8).trim();
    }

    /**
     * Returns the UTC time as a string.
     */
    public String getUtcTime() {
        return new String(utcTime, StandardCharsets.UTF_8).trim();
    }

    /**
     * Checks if the given flag is set.
     */
    public boolean hasFlag(long flag) {
        return flags != null && (flags.longValue() & flag) != 0;
    }

    /**
     * Checks if the token has RNG capability.
     */
    public boolean hasRng() {
        return hasFlag(TokenFlags.RNG);
    }

    /**
     * Checks if the token is write protected.
     */
    public boolean isWriteProtected() {
        return hasFlag(TokenFlags.WRITE_PROTECTED);
    }

    /**
     * Checks if login is required.
     */
    public boolean isLoginRequired() {
        return hasFlag(TokenFlags.LOGIN_REQUIRED);
    }

    /**
     * Checks if user PIN is initialized.
     */
    public boolean isUserPinInitialized() {
        return hasFlag(TokenFlags.USER_PIN_INITIALIZED);
    }

    /**
     * Checks if the token is initialized.
     */
    public boolean isTokenInitialized() {
        return hasFlag(TokenFlags.TOKEN_INITIALIZED);
    }

    /**
     * Checks if user PIN is locked.
     */
    public boolean isUserPinLocked() {
        return hasFlag(TokenFlags.USER_PIN_LOCKED);
    }

    /**
     * Checks if restore key not needed.
     */
    public boolean isRestoreKeyNotNeeded() {
        return hasFlag(TokenFlags.RESTORE_KEY_NOT_NEEDED);
    }

    /**
     * Checks if token has clock.
     */
    public boolean hasClockOnToken() {
        return hasFlag(TokenFlags.CLOCK_ON_TOKEN);
    }

    /**
     * Checks if token supports protected authentication path.
     */
    public boolean hasProtectedAuthenticationPath() {
        return hasFlag(TokenFlags.PROTECTED_AUTHENTICATION_PATH);
    }

    /**
     * Checks if token supports dual crypto operations.
     */
    public boolean supportsDualCryptoOperations() {
        return hasFlag(TokenFlags.DUAL_CRYPTO_OPERATIONS);
    }

    public static class ByReference extends TokenInfo implements Structure.ByReference {}
    public static class ByValue extends TokenInfo implements Structure.ByValue {}
}
