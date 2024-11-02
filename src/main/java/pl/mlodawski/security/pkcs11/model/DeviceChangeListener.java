package pl.mlodawski.security.pkcs11.model;

/**
 * Interface for listening to PKCS#11 device changes.
 */
public interface DeviceChangeListener {
    /**
     * Called when a new device is connected.
     *
     * @param device the connected device
     */
    void onDeviceConnected(PKCS11Device device);

    /**
     * Called when a device is disconnected.
     *
     * @param device the disconnected device
     */
    void onDeviceDisconnected(PKCS11Device device);

    /**
     * Called when a device's state changes.
     *
     * @param device    the device whose state changed
     * @param oldState  the previous state of the device
     */
    void onDeviceStateChanged(PKCS11Device device, DeviceState oldState);

    /**
     * Called when a device encounters an error.
     *
     * @param device    the device that encountered an error
     * @param error     the error that occurred
     */
    void onDeviceError(PKCS11Device device, Exception error);
}
