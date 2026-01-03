package pl.mlodawski.security.pkcs11;

import lombok.extern.slf4j.Slf4j;

import com.sun.jna.NativeLong;
import com.sun.jna.ptr.NativeLongByReference;

import pl.mlodawski.security.pkcs11.exceptions.DeviceManagerException;
import pl.mlodawski.security.pkcs11.model.DeviceCapability;
import pl.mlodawski.security.pkcs11.model.DeviceChangeListener;
import pl.mlodawski.security.pkcs11.model.DeviceState;
import pl.mlodawski.security.pkcs11.model.PKCS11Device;
import pl.mlodawski.security.pkcs11.jna.Cryptoki;
import pl.mlodawski.security.pkcs11.jna.constants.ReturnValue;
import pl.mlodawski.security.pkcs11.jna.structure.InitializeArgs;
import pl.mlodawski.security.pkcs11.jna.structure.SlotInfo;
import pl.mlodawski.security.pkcs11.jna.structure.TokenInfo;

import java.util.*;
import java.util.concurrent.*;
import java.util.stream.Collectors;


@Slf4j
public class PKCS11DeviceManager implements AutoCloseable {
    /**
     * The initial delay (in seconds) before the device monitoring task starts executing.
     * This variable is used to configure the delay period to allow the system to initialize
     * properly before beginning the device monitoring procedures.
     */
    private static final int DEVICE_MONITOR_INITIAL_DELAY = 0;
    /**
     * Represents the period in seconds at which the devices are monitored.
     * This constant defines how frequently the monitoring service will check the status of the devices.
     * A lower value indicates more frequent checks, whereas a higher value means less frequent checks.
     */
    private static final int DEVICE_MONITOR_PERIOD = 2;
    /**
     * Represents the time unit used for device monitoring intervals.
     * This constant defines the unit of time as seconds and is used
     * to specify how frequently the system checks the status or performance
     * metrics of monitored devices.
     */
    private static final TimeUnit DEVICE_MONITOR_TIME_UNIT = TimeUnit.SECONDS;
    /**
     * Constant indicating the presence of a token.
     * This byte value is used to represent a state
     * where a token is present in the system.
     */
    private static final byte TOKEN_PRESENT = 1;

    /**
     * Represents an instance of the PKCS#11 cryptographic token interface.
     * This variable is used for performing cryptographic operations such as
     * encryption, decryption, signing, and key management.
     * Being `final`, it ensures that the reference to the PKCS#11 provider
     * cannot be changed once initialized, providing immutability and
     * thread-safety guarantees.
     */
    private final Cryptoki pkcs11;
    /**
     * A map that holds PKCS11Device instances identified by their respective
     * NativeLong keys. This variable is used to manage and access the collection
     * of devices associated with their unique identifiers.
     */
    private final Map<NativeLong, PKCS11Device> devices;
    /**
     * A set of listeners that are notified when a device change event occurs.
     * DeviceChangeListener is the interface for handling changes in device states.
     * Listeners in this set are registered to receive notifications about
     * device alterations, additions, or removals.
     */
    private final Set<DeviceChangeListener> listeners;
    /**
     * A ScheduledExecutorService that is tasked with monitoring device activities.
     * It schedules and executes monitoring tasks at fixed intervals
     * to ensure devices are functioning correctly and efficiently.
     */
    private ScheduledExecutorService deviceMonitor;
    /**
     * A lock object used to synchronize the reinitialization process to ensure
     * thread-safety. This object is employed to prevent concurrent modification
     * of resources that need to be reinitialized, providing a mechanism for
     * mutual exclusion.
     */
    private final Object reinitLock = new Object();

    /**
     * A flag indicating whether the process or thread is currently running.
     * This variable is marked as volatile to ensure visibility of its
     * changes across multiple threads.
     */
    private volatile boolean isRunning;

    /**
     * Constructs a PKCS11DeviceManager instance.
     *
     * @param pkcs11 the PKCS11 instance to manage
     * @throws IllegalArgumentException if pkcs11 is null
     */
    public PKCS11DeviceManager(final Cryptoki pkcs11) {
        if (pkcs11 == null) {
            throw new IllegalArgumentException("pkcs11 cannot be null");
        }
        this.pkcs11 = pkcs11;
        this.devices = new ConcurrentHashMap<>();
        this.listeners = new CopyOnWriteArraySet<>();
        this.deviceMonitor = Executors.newSingleThreadScheduledExecutor(r -> {
            Thread t = new Thread(r, "PKCS11-Device-Monitor");
            t.setDaemon(true);
            return t;
        });
        this.isRunning = false;

        initializeDeviceList();
        startDeviceMonitoring();
    }


    /**
     * Initializes the device list by querying available slots and adding each corresponding device.
     *
     * This method interacts with the PKCS#11 library to retrieve the available slot count
     * and then gets the list of active slots. For each slot, it attempts to initialize a device.
     * If any step fails, a `DeviceManagerException` is thrown.
     *
     * @throws DeviceManagerException if there is any error during the initialization of the device list.
     */
    private void initializeDeviceList() {
        try {
            NativeLongByReference slotCount = new NativeLongByReference();
            NativeLong rv = pkcs11.C_GetSlotList(TOKEN_PRESENT, null, slotCount);
            if (!ReturnValue.isSuccess(rv)) {
                throw new DeviceManagerException("Failed to get slot count, error: " + rv.longValue(), null);
            }

            if (slotCount.getValue().longValue() > 0) {
                NativeLong[] slots = new NativeLong[slotCount.getValue().intValue()];
                rv = pkcs11.C_GetSlotList(TOKEN_PRESENT, slots, slotCount);
                if (!ReturnValue.isSuccess(rv)) {
                    throw new DeviceManagerException("Failed to get slot list, error: " + rv.longValue(), null);
                }

                for (NativeLong slot : slots) {
                    try {
                        addDevice(slot);
                    } catch (Exception e) {
                        log.error("Failed to initialize device for slot {}", slot, e);
                    }
                }
            }
        } catch (Exception e) {
            log.error("Failed to initialize device list", e);
            throw new DeviceManagerException("Failed to initialize device list", e);
        }
    }

    /**
     * Refreshes the list of devices by querying the available slots through the PKCS#11 interface.
     * This method retrieves the count of available slots, and if slots are available,
     * it fetches the slot identifiers and attempts to add each device found in the slots.
     *
     * Any errors encountered during the slot querying or device addition process are logged.
     * If the method fails to refresh the device list, it throws a DeviceManagerException.
     *
     * @throws DeviceManagerException if any error occurs during the device list refresh process
     */
    private void refreshDeviceList() {
        try {
            NativeLongByReference slotCount = new NativeLongByReference();
            NativeLong rv = pkcs11.C_GetSlotList(TOKEN_PRESENT, null, slotCount);
            if (!ReturnValue.isSuccess(rv)) {
                log.error("Failed to get slot count, error: {}", rv.longValue());
                return;
            }

            if (slotCount.getValue().longValue() > 0) {
                NativeLong[] slots = new NativeLong[slotCount.getValue().intValue()];
                rv = pkcs11.C_GetSlotList(TOKEN_PRESENT, slots, slotCount);
                if (!ReturnValue.isSuccess(rv)) {
                    log.error("Failed to get slot list, error: {}", rv.longValue());
                    return;
                }

                for (NativeLong slot : slots) {
                    try {
                        addDevice(slot);
                    } catch (Exception e) {
                        log.error("Failed to add device for slot {}", slot, e);
                    }
                }
            }
        } catch (Exception e) {
            log.error("Error refreshing device list", e);
            throw new DeviceManagerException("Failed to refresh device list", e);
        }
    }

    /**
     * Performs a soft reset of the device manager.
     *
     * This method halts any ongoing device monitoring activities, clears the existing device list,
     * reinitializes the device monitor, refreshes the device list, and then starts device monitoring again.
     * It ensures that the operations are thread-safe by synchronizing on the reinitialization lock.
     *
     * If an error occurs during the soft reset process, a log entry is created,
     * and a DeviceManagerException is thrown.
     *
     * @throws DeviceManagerException If the soft reset process fails due to any exception.
     */
    public void softReset() {
        synchronized (reinitLock) {
            try {
                isRunning = false;
                stopDeviceMonitoring();
                devices.clear();
                deviceMonitor = createDeviceMonitor();
                refreshDeviceList();
                startDeviceMonitoring();
            } catch (Exception e) {
                log.error("Error during soft reset", e);
                throw new DeviceManagerException("Failed to perform soft reset", e);
            }
        }
    }

    /**
     * Prepares the system for a device change by performing a soft reset.
     *
     * This method synchronizes on the reinitLock object to ensure that
     * only one thread can perform the preparation process at a time.
     * It attempts to perform a soft reset, and if an exception occurs,
     * it logs an error message and throws a DeviceManagerException with
     * the original exception as the cause.
     *
     * @throws DeviceManagerException if the preparation for device change fails.
     */
    public void prepareForDeviceChange() {
        synchronized (reinitLock) {
            try {
                softReset();
            } catch (Exception e) {
                log.error("Error preparing for device change", e);
                throw new DeviceManagerException("Failed to prepare for device change", e);
            }
        }
    }

    /**
     * Stops the device monitoring process if it is currently active.
     * This method shuts down the device monitor gracefully by waiting for existing tasks to complete within a timeout period.
     * If the device monitor does not terminate within the specified timeout, it is forced to shut down immediately.
     * If the current thread is interrupted while waiting, it re-interrupts the thread and forces the device monitor to shut down.
     */
    private void stopDeviceMonitoring() {
        if (deviceMonitor != null && !deviceMonitor.isShutdown()) {
            deviceMonitor.shutdown();
            try {
                if (!deviceMonitor.awaitTermination(5, TimeUnit.SECONDS)) {
                    deviceMonitor.shutdownNow();
                }
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                deviceMonitor.shutdownNow();
            }
        }
    }

    /**
     * Creates a ScheduledExecutorService for monitoring PKCS11 devices.
     * The executor runs with a single daemon thread named "PKCS11-Device-Monitor".
     *
     * @return a ScheduledExecutorService for device monitoring tasks
     */
    private ScheduledExecutorService createDeviceMonitor() {
        return Executors.newSingleThreadScheduledExecutor(r -> {
            Thread t = new Thread(r, "PKCS11-Device-Monitor");
            t.setDaemon(true);
            return t;
        });
    }

    /**
     * Reinitializes the device manager. This method ensures that any ongoing device
     * monitoring is stopped, clears the current list of devices, finalizes the PKCS#11
     * library, reinitializes it, and then restarts the device monitoring process.
     *
     * It performs the following steps:
     * 1. Stops device monitoring if it is currently running.
     * 2. Clears the list of managed devices.
     * 3. Finalizes the PKCS#11 library.
     * 4. Initializes the PKCS#11 library with default arguments.
     * 5. Creates and starts a new device monitoring process.
     *
     * @throws DeviceManagerException if there is any error during reinitialization,
     *                                including failure to initialize the PKCS#11 library.
     */
    public void reinitialize() {
        synchronized (reinitLock) {
            try {
                isRunning = false;
                stopDeviceMonitoring();
                devices.clear();
                try {
                    pkcs11.C_Finalize(null);
                } catch (Exception e) {
                    log.debug("C_Finalize threw exception (might be already finalized)", e);
                }

                InitializeArgs initArgs = new InitializeArgs();
                initArgs.flags = new NativeLong(0);
                initArgs.pReserved = null;

                NativeLong rv = pkcs11.C_Initialize(initArgs);
                if (!ReturnValue.isSuccess(rv) &&
                        rv.longValue() != ReturnValue.CRYPTOKI_ALREADY_INITIALIZED) {
                    throw new DeviceManagerException("Failed to initialize PKCS#11, error: " + rv.longValue(), null);
                }
                deviceMonitor = createDeviceMonitor();
                initializeDeviceList();
                startDeviceMonitoring();
            } catch (Exception e) {
                log.error("Error during device manager reinitialization", e);
                throw new DeviceManagerException("Failed to reinitialize device manager", e);
            }
        }
    }


    /**
     * Starts monitoring for device changes.
     */
    private void startDeviceMonitoring() {
        isRunning = true;
        deviceMonitor.scheduleAtFixedRate(
                this::checkDevices,
                DEVICE_MONITOR_INITIAL_DELAY,
                DEVICE_MONITOR_PERIOD,
                DEVICE_MONITOR_TIME_UNIT
        );
    }

    /**
     * Checks for device changes and updates the device list accordingly.
     */
    private void checkDevices() {
        try {
            NativeLongByReference slotCount = new NativeLongByReference();
            NativeLong rv = pkcs11.C_GetSlotList(TOKEN_PRESENT, null, slotCount);
            if (!ReturnValue.isSuccess(rv)) {
                log.error("Failed to get slot count, error: {}", rv.longValue());
                return;
            }

            if (slotCount.getValue().longValue() > 0) {
                NativeLong[] currentSlots = new NativeLong[slotCount.getValue().intValue()];
                rv = pkcs11.C_GetSlotList(TOKEN_PRESENT, currentSlots, slotCount);
                if (!ReturnValue.isSuccess(rv)) {
                    log.error("Failed to get slot list, error: {}", rv.longValue());
                    return;
                }

                Set<NativeLong> currentSlotSet = new HashSet<>(Arrays.asList(currentSlots));
                Set<NativeLong> existingSlotSet = new HashSet<>(devices.keySet());

                existingSlotSet.stream()
                        .filter(slot -> !currentSlotSet.contains(slot))
                        .forEach(this::removeDevice);

                currentSlotSet.stream()
                        .filter(slot -> !existingSlotSet.contains(slot))
                        .forEach(this::addDevice);

                devices.values().forEach(device -> {
                    DeviceState oldState = device.getState();
                    if (device.updateState() && oldState != device.getState()) {
                        notifyDeviceStateChanged(device, oldState);
                    }
                });
            }
        } catch (Exception e) {
            log.error("Error checking for device changes", e);
        }
    }

    /**
     * Adds a new device to the manager.
     *
     * @param slot the slot ID of the device to add
     */
    private void addDevice(NativeLong slot) {
        try {
            SlotInfo slotInfo = new SlotInfo();
            TokenInfo tokenInfo = new TokenInfo();

            NativeLong rv = pkcs11.C_GetSlotInfo(slot, slotInfo);
            if (!ReturnValue.isSuccess(rv)) {
                log.error("Failed to get slot info for slot {}, error: {}", slot, rv);
                return;
            }

            rv = pkcs11.C_GetTokenInfo(slot, tokenInfo);
            if (!ReturnValue.isSuccess(rv)) {
                log.error("Failed to get token info for slot {}, error: {}", slot, rv);
                return;
            }

            PKCS11Device device = new PKCS11Device(slot, pkcs11, slotInfo, tokenInfo);
            devices.put(slot, device);
            notifyDeviceConnected(device);
        } catch (Exception e) {
            log.error("Error adding device for slot {}", slot, e);
        }
    }

    /**
     * Removes a device from the manager.
     *
     * @param slot the slot ID of the device to remove
     */
    private void removeDevice(NativeLong slot) {
        PKCS11Device device = devices.remove(slot);
        if (device != null) {
            notifyDeviceDisconnected(device);
        }
    }

    /**
     * Registers a device change listener.
     *
     * @param listener the listener to register
     * @throws IllegalArgumentException if listener is null
     */
    public void registerDeviceChangeListener(DeviceChangeListener listener) {
        if (listener == null) {
            throw new IllegalArgumentException("listener cannot be null");
        }
        listeners.add(listener);
    }

    /**
     * Unregisters a device change listener.
     *
     * @param listener the listener to unregister
     */
    public void unregisterDeviceChangeListener(DeviceChangeListener listener) {
        listeners.remove(listener);
    }

    /**
     * Lists all available devices.
     *
     * @return an unmodifiable list of all available devices
     */
    public List<PKCS11Device> listDevices() {
        return Collections.unmodifiableList(new ArrayList<>(devices.values()));
    }

    /**
     * Gets a device by its slot ID.
     *
     * @param slotId the slot ID of the device
     * @return an Optional containing the device if found, empty otherwise
     */
    public Optional<PKCS11Device> getDevice(NativeLong slotId) {
        return Optional.ofNullable(devices.get(slotId));
    }

    /**
     * Lists devices by their state.
     *
     * @param state the state to filter by
     * @return an unmodifiable list of devices in the specified state
     */
    public List<PKCS11Device> listDevicesByState(DeviceState state) {
        return devices.values().stream()
                .filter(device -> device.getState() == state)
                .collect(Collectors.collectingAndThen(
                        Collectors.toList(),
                        Collections::unmodifiableList
                ));
    }

    /**
     * Lists devices by their capabilities.
     *
     * @param capability the capability to filter by
     * @return an unmodifiable list of devices with the specified capability
     */
    public List<PKCS11Device> listDevicesByCapability(DeviceCapability capability) {
        return devices.values().stream()
                .filter(device -> device.hasCapability(capability))
                .collect(Collectors.collectingAndThen(
                        Collectors.toList(),
                        Collections::unmodifiableList
                ));
    }

    /**
     * Notifies listeners about a device connection.
     *
     * @param device the connected device
     */
    private void notifyDeviceConnected(PKCS11Device device) {
        for (DeviceChangeListener listener : listeners) {
            try {
                listener.onDeviceConnected(device);
            } catch (Exception e) {
                log.error("Error notifying listener about device connection", e);
            }
        }
    }

    /**
     * Notifies listeners about a device disconnection.
     *
     * @param device the disconnected device
     */
    private void notifyDeviceDisconnected(PKCS11Device device) {
        for (DeviceChangeListener listener : listeners) {
            try {
                listener.onDeviceDisconnected(device);
            } catch (Exception e) {
                log.error("Error notifying listener about device disconnection", e);
            }
        }
    }

    /**
     * Notifies listeners about a device state change.
     *
     * @param device   the device whose state changed
     * @param oldState the previous state of the device
     */
    private void notifyDeviceStateChanged(PKCS11Device device, DeviceState oldState) {
        for (DeviceChangeListener listener : listeners) {
            try {
                listener.onDeviceStateChanged(device, oldState);
            } catch (Exception e) {
                log.error("Error notifying listener about device state change", e);
            }
        }
    }

    /**
     * Stops the device manager and releases resources.
     */
    @Override
    public void close() {
        synchronized (reinitLock) {
            isRunning = false;
            stopDeviceMonitoring();
            devices.clear();
            listeners.clear();
            try {
                pkcs11.C_Finalize(null);
            } catch (Exception e) {
                log.debug("C_Finalize threw exception during close", e);
            }
        }
    }

}