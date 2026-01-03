package pl.mlodawski.security.pkcs11.jna.structure;

import com.sun.jna.NativeLong;
import com.sun.jna.Structure;
import pl.mlodawski.security.pkcs11.jna.constants.TokenFlags;

import java.nio.charset.StandardCharsets;

/**
 * PKCS#11 CK_SLOT_INFO structure.
 * Provides information about a slot.
 * Based on OASIS PKCS#11 specification.
 */
@Structure.FieldOrder({"slotDescription", "manufacturerID", "flags", "hardwareVersion", "firmwareVersion"})
public class SlotInfo extends Structure {

    /**
     * Slot description (64 bytes, blank padded).
     */
    public byte[] slotDescription = new byte[64];

    /**
     * Manufacturer ID (32 bytes, blank padded).
     */
    public byte[] manufacturerID = new byte[32];

    /**
     * Bit flags indicating slot capabilities.
     */
    public NativeLong flags;

    /**
     * Hardware version.
     */
    public Version hardwareVersion;

    /**
     * Firmware version.
     */
    public Version firmwareVersion;

    public SlotInfo() {
        super();
    }

    /**
     * Returns the slot description as a trimmed string.
     */
    public String getSlotDescription() {
        return new String(slotDescription, StandardCharsets.UTF_8).trim();
    }

    /**
     * Returns the manufacturer ID as a trimmed string.
     */
    public String getManufacturerID() {
        return new String(manufacturerID, StandardCharsets.UTF_8).trim();
    }

    /**
     * Checks if a token is present in the slot.
     */
    public boolean isTokenPresent() {
        return hasFlag(TokenFlags.TOKEN_PRESENT);
    }

    /**
     * Checks if the slot has a removable device.
     */
    public boolean isRemovableDevice() {
        return hasFlag(TokenFlags.REMOVABLE_DEVICE);
    }

    /**
     * Checks if the slot is a hardware slot.
     */
    public boolean isHardwareSlot() {
        return hasFlag(TokenFlags.HW_SLOT);
    }

    /**
     * Checks if the given flag is set.
     */
    public boolean hasFlag(long flag) {
        return flags != null && (flags.longValue() & flag) != 0;
    }

    public static class ByReference extends SlotInfo implements Structure.ByReference {}
    public static class ByValue extends SlotInfo implements Structure.ByValue {}
}
