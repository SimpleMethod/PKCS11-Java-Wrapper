package pl.mlodawski.security.pkcs11.model;

import com.sun.jna.NativeLong;
import lombok.Getter;
import lombok.extern.slf4j.Slf4j;
import pl.mlodawski.security.pkcs11.exceptions.DeviceInfoRetrievalException;
import pl.mlodawski.security.pkcs11.jna.Cryptoki;
import pl.mlodawski.security.pkcs11.jna.constants.ReturnValue;
import pl.mlodawski.security.pkcs11.jna.constants.TokenFlags;
import pl.mlodawski.security.pkcs11.jna.structure.SlotInfo;
import pl.mlodawski.security.pkcs11.jna.structure.TokenInfo;

import java.util.*;

@Slf4j
@Getter
public class PKCS11Device {
    private final NativeLong slotId;
    private final Cryptoki pkcs11;
    private final String label;
    private final String manufacturer;
    private final String model;
    private final String serialNumber;
    private final SlotInfo slotInfo;
    private final TokenInfo tokenInfo;
    private final Set<DeviceCapability> capabilities;
    private volatile DeviceState state;

    /**
     * Constructs a PKCS11Device instance.
     *
     * @param slotId    the slot ID of the device
     * @param pkcs11    the Cryptoki instance
     * @param slotInfo  the slot information
     * @param tokenInfo the token information
     * @throws IllegalArgumentException if any required parameter is null
     */
    public PKCS11Device(NativeLong slotId, Cryptoki pkcs11, SlotInfo slotInfo, TokenInfo tokenInfo) {
        if (slotId == null || pkcs11 == null || slotInfo == null || tokenInfo == null) {
            throw new IllegalArgumentException("All constructor parameters are required");
        }

        this.slotId = slotId;
        this.pkcs11 = pkcs11;
        this.slotInfo = slotInfo;
        this.tokenInfo = tokenInfo;

        this.label = new String(tokenInfo.label).trim();
        this.manufacturer = new String(tokenInfo.manufacturerID).trim();
        this.model = new String(tokenInfo.model).trim();
        this.serialNumber = new String(tokenInfo.serialNumber).trim();

        this.capabilities = determineDeviceCapabilities();
        this.state = determineInitialState();
    }

    /**
     * Determines the initial state of the device.
     *
     * @return the current state of the device
     */
    private DeviceState determineInitialState() {
        try {
            long flags = tokenInfo.flags.longValue();

            if (!TokenFlags.hasFlag(flags, TokenFlags.TOKEN_PRESENT)) {
                return DeviceState.NOT_PRESENT;
            }

            if (!TokenFlags.hasFlag(flags, TokenFlags.TOKEN_INITIALIZED)) {
                return DeviceState.NOT_INITIALIZED;
            }

            if (!TokenFlags.hasFlag(flags, TokenFlags.USER_PIN_INITIALIZED)) {
                return DeviceState.PIN_NOT_INITIALIZED;
            }

            if (TokenFlags.hasFlag(flags, TokenFlags.USER_PIN_LOCKED)) {
                return DeviceState.PIN_LOCKED;
            }

            return DeviceState.READY;
        } catch (Exception e) {
            log.error("Error determining device state for slot {}", slotId, e);
            return DeviceState.ERROR;
        }
    }


    /**
     * Determines the capabilities of the device based on token flags.
     *
     * @return a set of device capabilities
     */
    private Set<DeviceCapability> determineDeviceCapabilities() {
        Set<DeviceCapability> caps = EnumSet.noneOf(DeviceCapability.class);
        long flags = tokenInfo.flags.longValue();

        if (TokenFlags.hasFlag(flags, TokenFlags.RNG)) {
            caps.add(DeviceCapability.RANDOM_NUMBER_GENERATION);
        }
        if (!TokenFlags.hasFlag(flags, TokenFlags.WRITE_PROTECTED)) {
            caps.add(DeviceCapability.WRITE_ENABLED);
        }
        if (TokenFlags.hasFlag(flags, TokenFlags.LOGIN_REQUIRED)) {
            caps.add(DeviceCapability.LOGIN_REQUIRED);
        }
        if (TokenFlags.hasFlag(flags, TokenFlags.RESTORE_KEY_NOT_NEEDED)) {
            caps.add(DeviceCapability.KEY_RESTORATION_NOT_NEEDED);
        }
        if (TokenFlags.hasFlag(flags, TokenFlags.CLOCK_ON_TOKEN)) {
            caps.add(DeviceCapability.CLOCK_AVAILABLE);
        }
        if (TokenFlags.hasFlag(flags, TokenFlags.PROTECTED_AUTHENTICATION_PATH)) {
            caps.add(DeviceCapability.PROTECTED_AUTHENTICATION_PATH);
        }
        if (TokenFlags.hasFlag(flags, TokenFlags.DUAL_CRYPTO_OPERATIONS)) {
            caps.add(DeviceCapability.DUAL_CRYPTO_OPERATIONS);
        }

        return Collections.unmodifiableSet(caps);
    }

    /**
     * Updates the device state by refreshing token information.
     *
     * @return true if the state was successfully updated, false otherwise
     */
    public boolean updateState() {
        try {
            TokenInfo newTokenInfo = new TokenInfo();
            NativeLong rv = pkcs11.C_GetTokenInfo(slotId, newTokenInfo);

            if (!ReturnValue.isSuccess(rv)) {
                log.error("Failed to get token info for slot {}, error: {}", slotId, rv);
                state = DeviceState.ERROR;
                return false;
            }

            state = determineInitialState();
            return true;
        } catch (Exception e) {
            log.error("Error updating device state for slot {}", slotId, e);
            state = DeviceState.ERROR;
            return false;
        }
    }

    /**
     * Checks if the device supports a specific capability.
     *
     * @param capability the capability to check
     * @return true if the device supports the capability, false otherwise
     */
    public boolean hasCapability(DeviceCapability capability) {
        return capabilities.contains(capability);
    }

    /**
     * Gets detailed information about the device.
     *
     * @return a map containing detailed device information
     */
    public Map<String, String> getDetailedInfo() {
        try {
            Map<String, String> info = new LinkedHashMap<>();
            info.put("Slot ID", slotId.toString());
            info.put("Label", label);
            info.put("Manufacturer", manufacturer);
            info.put("Model", model);
            info.put("Serial Number", serialNumber);

            info.put("Firmware Version", String.format("%d.%d",
                    tokenInfo.firmwareVersion.major & 0xFF,
                    tokenInfo.firmwareVersion.minor & 0xFF));
            info.put("Hardware Version", String.format("%d.%d",
                    tokenInfo.hardwareVersion.major & 0xFF,
                    tokenInfo.hardwareVersion.minor & 0xFF));

            info.put("Max Session Count", String.valueOf(tokenInfo.ulMaxSessionCount.longValue()));
            info.put("Min PIN Length", String.valueOf(tokenInfo.ulMinPinLen.longValue()));
            info.put("Max PIN Length", String.valueOf(tokenInfo.ulMaxPinLen.longValue()));
            info.put("Total Public Memory", String.valueOf(tokenInfo.ulTotalPublicMemory.longValue()));
            info.put("Free Public Memory", String.valueOf(tokenInfo.ulFreePublicMemory.longValue()));
            info.put("Total Private Memory", String.valueOf(tokenInfo.ulTotalPrivateMemory.longValue()));
            info.put("Free Private Memory", String.valueOf(tokenInfo.ulFreePrivateMemory.longValue()));
            info.put("Supported Capabilities", capabilities.toString());
            info.put("Current State", state.toString());

            return Collections.unmodifiableMap(info);
        } catch (Exception e) {
            log.error("Error getting detailed device info for slot {}", slotId, e);
            throw new DeviceInfoRetrievalException("Failed to get detailed device information", e);
        }
    }

    /**
     * Gets the maximum and minimum PIN length requirements.
     *
     * @return a map containing the min and max PIN lengths
     */
    public Map<String, Long> getPinLengthRequirements() {
        Map<String, Long> requirements = new HashMap<>();
        requirements.put("minLength", tokenInfo.ulMinPinLen.longValue());
        requirements.put("maxLength", tokenInfo.ulMaxPinLen.longValue());
        return Collections.unmodifiableMap(requirements);
    }

    /**
     * Checks if the device is in a ready state.
     *
     * @return true if the device is ready for operations, false otherwise
     */
    public boolean isReady() {
        return state == DeviceState.READY;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (!(o instanceof PKCS11Device)) return false;
        PKCS11Device that = (PKCS11Device) o;
        return Objects.equals(slotId, that.slotId) &&
                Objects.equals(serialNumber, that.serialNumber);
    }

    @Override
    public int hashCode() {
        return Objects.hash(slotId, serialNumber);
    }

    @Override
    public String toString() {
        return String.format("PKCS11Device[slotId=%s, label=%s, manufacturer=%s, model=%s, serialNumber=%s, state=%s]",
                slotId, label, manufacturer, model, serialNumber, state);
    }
}
