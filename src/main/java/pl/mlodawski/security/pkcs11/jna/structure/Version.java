package pl.mlodawski.security.pkcs11.jna.structure;

import com.sun.jna.Structure;

import java.util.Arrays;
import java.util.List;

/**
 * PKCS#11 CK_VERSION structure.
 * Represents a version number with major and minor components.
 * Based on OASIS PKCS#11 specification.
 */
@Structure.FieldOrder({"major", "minor"})
public class Version extends Structure {

    /**
     * Major version number (0-255).
     */
    public byte major;

    /**
     * Minor version number (0-255).
     */
    public byte minor;

    public Version() {
        super();
    }

    /**
     * Returns the version as a formatted string (e.g., "2.40").
     */
    public String getVersionString() {
        return String.format("%d.%d", Byte.toUnsignedInt(major), Byte.toUnsignedInt(minor));
    }

    @Override
    public String toString() {
        return getVersionString();
    }

    public static class ByReference extends Version implements Structure.ByReference {}
    public static class ByValue extends Version implements Structure.ByValue {}
}
