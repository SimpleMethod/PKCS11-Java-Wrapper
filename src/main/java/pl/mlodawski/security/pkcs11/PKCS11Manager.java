package pl.mlodawski.security.pkcs11;

import com.sun.jna.NativeLong;
import lombok.Getter;
import pl.mlodawski.security.pkcs11.exceptions.DeviceNotReadyException;
import pl.mlodawski.security.pkcs11.exceptions.PKCS11FinalizationException;
import pl.mlodawski.security.pkcs11.exceptions.PKCS11InitializationException;
import pl.mlodawski.security.pkcs11.model.DeviceChangeListener;
import pl.mlodawski.security.pkcs11.model.DeviceState;
import pl.mlodawski.security.pkcs11.model.PKCS11Device;
import pl.mlodawski.security.pkcs11.jna.Cryptoki;

import eu.europa.esig.dss.token.Pkcs11SignatureToken;
import lombok.extern.slf4j.Slf4j;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

import java.nio.file.Path;
import java.security.Security;
import java.util.List;
import java.util.Optional;

@Slf4j
public class PKCS11Manager implements AutoCloseable {
    @Getter
    private final Cryptoki pkcs11;
    private final Path libraryPath;
    private final PKCS11DeviceManager deviceManager;

    /**
     * Initializes a PKCS11Manager with the specified library path.
     *
     * @param libraryPath the path of the PKCS#11 library file
     * @throws IllegalArgumentException if libraryPath is null
     * @throws RuntimeException if PKCS#11 initialization fails
     */
    public PKCS11Manager(Path libraryPath) {
        if (libraryPath == null) {
            throw new IllegalArgumentException("libraryPath cannot be null");
        }

        Security.addProvider(new BouncyCastleProvider());
        this.libraryPath = libraryPath;

        try {
            this.pkcs11 = PKCS11Initializer.initializePkcs11(libraryPath);
            this.deviceManager = new PKCS11DeviceManager(pkcs11);
        } catch (Exception e) {
            log.error("PKCS#11 initialization failed", e);
            throw new PKCS11InitializationException("PKCS#11 initialization failed", e);
        }
    }

    /**
     * Lists all available devices.
     *
     * @return list of available PKCS11 devices
     */
    public List<PKCS11Device> listDevices() {
        return deviceManager.listDevices();
    }

    /**
     * Lists devices by their state.
     *
     * @param state the state to filter by
     * @return list of devices in the specified state
     */
    public List<PKCS11Device> listDevicesByState(DeviceState state) {
        return deviceManager.listDevicesByState(state);
    }

    /**
     * Reinitializes the system state to handle changes in the connected device.
     *
     * This method performs cleanup of the current device manager state by
     * attempting to close it. If an exception occurs during the cleanup
     * process, a warning message is logged. This is typically used when
     * a device change event is detected, and the system needs to reset its
     * state to accommodate the new device configuration.
     */
    public void reinitializeForDeviceChange() {
        try {
            deviceManager.reinitialize();
        } catch (Exception e) {
            log.error("Error reinitializing device manager", e);
            throw new PKCS11InitializationException("Failed to reinitialize device manager", e);
        }
    }

    public void prepareForDeviceChange() {
        deviceManager.prepareForDeviceChange();
    }



    /**
     * Gets a device by its slot ID.
     *
     * @param slotId the slot ID of the device
     * @return Optional containing the device if found
     */
    public Optional<PKCS11Device> getDevice(NativeLong slotId) {
        return deviceManager.getDevice(slotId);
    }

    /**
     * Opens a session with the specified device.
     *
     * @param device the PKCS11 device
     * @param pin    the PIN for authentication
     * @return a PKCS11Session object
     * @throws IllegalArgumentException if device or pin is null
     * @throws DeviceNotReadyException if device is not in ready state
     * @throws RuntimeException if session creation fails
     */
    public PKCS11Session openSession(PKCS11Device device, String pin) {
        if (device == null) {
            throw new IllegalArgumentException("device cannot be null");
        }
        if (pin == null || pin.isEmpty()) {
            throw new IllegalArgumentException("pin cannot be null or empty");
        }

        if (!device.isReady()) {
            throw new DeviceNotReadyException("Device is not in ready state: " + device.getState(),null);
        }

        return new PKCS11Session(pkcs11, pin, device.getSlotId().intValue());
    }

    /**
     * Registers a device change listener.
     *
     * @param listener the listener to register
     */
    public void registerDeviceChangeListener(DeviceChangeListener listener) {
        deviceManager.registerDeviceChangeListener(listener);
    }

    /**
     * Unregisters a device change listener.
     *
     * @param listener the listener to unregister
     */
    public void unregisterDeviceChangeListener(DeviceChangeListener listener) {
        deviceManager.unregisterDeviceChangeListener(listener);
    }

    /**
     * Creates a PKCS#11 signature token for the specified device and PIN.
     *
     * @param device the PKCS11 device
     * @param pin    the PIN for authentication
     * @return a Pkcs11SignatureToken object
     * @throws IllegalArgumentException if device or pin is null
     * @throws DeviceNotReadyException if device is not in ready state
     */
    public Pkcs11SignatureToken getPKCS11Token(PKCS11Device device, String pin) {
        if (device == null) {
            throw new IllegalArgumentException("device cannot be null");
        }
        if (pin == null || pin.isEmpty()) {
            throw new IllegalArgumentException("pin cannot be null or empty");
        }

        if (!device.isReady()) {
            throw new DeviceNotReadyException("Device is not in ready state: " + device.getState(),null);
        }

        return new Pkcs11SignatureToken(libraryPath.toString(), pin::toCharArray);
    }

    /**
     * Closes the PKCS11Manager and releases resources.
     */
    @Override
    public void close() {
        try {
            deviceManager.close();
            pkcs11.C_Finalize(null);
        } catch (Exception e) {
            log.error("Failed to finalize PKCS#11", e);
            throw new PKCS11FinalizationException("Failed to finalize PKCS#11", e);
        }
    }
}
