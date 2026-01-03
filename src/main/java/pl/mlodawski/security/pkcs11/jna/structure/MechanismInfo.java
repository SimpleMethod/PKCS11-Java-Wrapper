package pl.mlodawski.security.pkcs11.jna.structure;

import com.sun.jna.NativeLong;
import com.sun.jna.Structure;
import pl.mlodawski.security.pkcs11.jna.constants.MechanismFlags;

/**
 * PKCS#11 CK_MECHANISM_INFO structure.
 * Provides information about a particular mechanism.
 * Based on OASIS PKCS#11 specification.
 */
@Structure.FieldOrder({"ulMinKeySize", "ulMaxKeySize", "flags"})
public class MechanismInfo extends Structure {

    /**
     * Minimum key size in bits or bytes (mechanism-dependent).
     */
    public NativeLong ulMinKeySize;

    /**
     * Maximum key size in bits or bytes (mechanism-dependent).
     */
    public NativeLong ulMaxKeySize;

    /**
     * Bit flags specifying mechanism capabilities.
     */
    public NativeLong flags;

    public MechanismInfo() {
        super();
    }

    /**
     * Returns the minimum key size.
     */
    public long getMinKeySize() {
        return ulMinKeySize != null ? ulMinKeySize.longValue() : 0;
    }

    /**
     * Returns the maximum key size.
     */
    public long getMaxKeySize() {
        return ulMaxKeySize != null ? ulMaxKeySize.longValue() : 0;
    }

    /**
     * Returns the flags value.
     */
    public long getFlags() {
        return flags != null ? flags.longValue() : 0;
    }

    /**
     * Checks if the given flag is set.
     */
    public boolean hasFlag(long flag) {
        return flags != null && (flags.longValue() & flag) != 0;
    }

    /**
     * Checks if mechanism is hardware-based.
     */
    public boolean isHardware() {
        return hasFlag(MechanismFlags.HW);
    }

    /**
     * Checks if mechanism supports encryption.
     */
    public boolean supportsEncrypt() {
        return hasFlag(MechanismFlags.ENCRYPT);
    }

    /**
     * Checks if mechanism supports decryption.
     */
    public boolean supportsDecrypt() {
        return hasFlag(MechanismFlags.DECRYPT);
    }

    /**
     * Checks if mechanism supports digest (hash).
     */
    public boolean supportsDigest() {
        return hasFlag(MechanismFlags.DIGEST);
    }

    /**
     * Checks if mechanism supports signing.
     */
    public boolean supportsSign() {
        return hasFlag(MechanismFlags.SIGN);
    }

    /**
     * Checks if mechanism supports verification.
     */
    public boolean supportsVerify() {
        return hasFlag(MechanismFlags.VERIFY);
    }

    /**
     * Checks if mechanism supports key generation.
     */
    public boolean supportsGenerate() {
        return hasFlag(MechanismFlags.GENERATE);
    }

    /**
     * Checks if mechanism supports key pair generation.
     */
    public boolean supportsGenerateKeyPair() {
        return hasFlag(MechanismFlags.GENERATE_KEY_PAIR);
    }

    /**
     * Checks if mechanism supports key wrapping.
     */
    public boolean supportsWrap() {
        return hasFlag(MechanismFlags.WRAP);
    }

    /**
     * Checks if mechanism supports key unwrapping.
     */
    public boolean supportsUnwrap() {
        return hasFlag(MechanismFlags.UNWRAP);
    }

    /**
     * Checks if mechanism supports key derivation.
     */
    public boolean supportsDerive() {
        return hasFlag(MechanismFlags.DERIVE);
    }

    public static class ByReference extends MechanismInfo implements Structure.ByReference {}
    public static class ByValue extends MechanismInfo implements Structure.ByValue {}
}
