package pl.mlodawski.security.pkcs11;

import com.sun.jna.NativeLong;
import com.sun.jna.ptr.NativeLongByReference;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import pl.mlodawski.security.pkcs11.exceptions.DeviceManagerException;
import pl.mlodawski.security.pkcs11.model.DeviceCapability;
import pl.mlodawski.security.pkcs11.model.DeviceChangeListener;
import pl.mlodawski.security.pkcs11.model.DeviceState;
import pl.mlodawski.security.pkcs11.model.PKCS11Device;
import ru.rutoken.pkcs11jna.*;

import java.util.List;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class PKCS11DeviceManagerTest {

    @Mock
    private Pkcs11 pkcs11Mock;

    @Mock
    private DeviceChangeListener listenerMock;

    private PKCS11DeviceManager deviceManager;
    private static final byte TOKEN_PRESENT = 1;

    @BeforeEach
    void setUp() {
        // Podstawowe mockowanie dla inicjalizacji
        lenient().when(pkcs11Mock.C_GetSlotList(eq(TOKEN_PRESENT), any(), any(NativeLongByReference.class)))
                .thenAnswer(inv -> {
                    NativeLongByReference count = inv.getArgument(2);
                    count.setValue(new NativeLong(1));
                    return new NativeLong(Pkcs11Constants.CKR_OK);
                });

        lenient().when(pkcs11Mock.C_GetSlotList(eq(TOKEN_PRESENT), any(NativeLong[].class), any(NativeLongByReference.class)))
                .thenAnswer(inv -> {
                    NativeLong[] slots = inv.getArgument(1);
                    slots[0] = new NativeLong(0);
                    return new NativeLong(Pkcs11Constants.CKR_OK);
                });

        lenient().when(pkcs11Mock.C_GetSlotInfo(any(NativeLong.class), any(CK_SLOT_INFO.class)))
                .thenReturn(new NativeLong(Pkcs11Constants.CKR_OK));

        lenient().when(pkcs11Mock.C_GetTokenInfo(any(NativeLong.class), any(CK_TOKEN_INFO.class)))
                .thenReturn(new NativeLong(Pkcs11Constants.CKR_OK));
    }

    @Test
    void constructor_nullPkcs11_shouldThrowException() {
        assertThrows(IllegalArgumentException.class, () -> new PKCS11DeviceManager(null));
    }



    @Test
    void listDevices_noDevices_shouldReturnEmptyList() {
        // Setup for no devices
        when(pkcs11Mock.C_GetSlotList(eq(TOKEN_PRESENT), any(), any(NativeLongByReference.class)))
                .thenAnswer(inv -> {
                    NativeLongByReference count = inv.getArgument(2);
                    count.setValue(new NativeLong(0));
                    return new NativeLong(Pkcs11Constants.CKR_OK);
                });

        deviceManager = new PKCS11DeviceManager(pkcs11Mock);
        List<PKCS11Device> devices = deviceManager.listDevices();

        assertTrue(devices.isEmpty());
    }

    @Test
    void listDevices_withDevices_shouldReturnDeviceList() {
        deviceManager = new PKCS11DeviceManager(pkcs11Mock);
        List<PKCS11Device> devices = deviceManager.listDevices();

        assertFalse(devices.isEmpty());
        assertEquals(1, devices.size());
    }

    @Test
    void getDevice_existingDevice_shouldReturnDevice() {
        deviceManager = new PKCS11DeviceManager(pkcs11Mock);
        Optional<PKCS11Device> device = deviceManager.getDevice(new NativeLong(0));

        assertTrue(device.isPresent());
    }

    @Test
    void getDevice_nonExistentDevice_shouldReturnEmpty() {
        deviceManager = new PKCS11DeviceManager(pkcs11Mock);
        Optional<PKCS11Device> device = deviceManager.getDevice(new NativeLong(999));

        assertFalse(device.isPresent());
    }

    @Test
    void listDevicesByState_shouldFilterByState() {
        deviceManager = new PKCS11DeviceManager(pkcs11Mock);
        List<PKCS11Device> devices = deviceManager.listDevicesByState(DeviceState.READY);

        assertNotNull(devices);
    }

    @Test
    void listDevicesByCapability_shouldFilterByCapability() {
        deviceManager = new PKCS11DeviceManager(pkcs11Mock);
        List<PKCS11Device> devices = deviceManager.listDevicesByCapability(DeviceCapability.WRITE_ENABLED);

        assertNotNull(devices);
    }

    @Test
    void deviceChangeListener_shouldReceiveNotifications() {
        deviceManager = new PKCS11DeviceManager(pkcs11Mock);
        deviceManager.registerDeviceChangeListener(listenerMock);

        // Simulate device connection by refreshing the list
        deviceManager.softReset();

        verify(listenerMock, atLeastOnce()).onDeviceConnected(any(PKCS11Device.class));
    }

    @Test
    void registerDeviceChangeListener_nullListener_shouldThrowException() {
        deviceManager = new PKCS11DeviceManager(pkcs11Mock);
        assertThrows(IllegalArgumentException.class, () -> deviceManager.registerDeviceChangeListener(null));
    }

    @Test
    void unregisterDeviceChangeListener_shouldRemoveListener() {
        deviceManager = new PKCS11DeviceManager(pkcs11Mock);
        deviceManager.registerDeviceChangeListener(listenerMock);
        deviceManager.unregisterDeviceChangeListener(listenerMock);

        deviceManager.softReset();

        verify(listenerMock, never()).onDeviceConnected(any(PKCS11Device.class));
    }

    @Test
    void softReset_shouldRefreshDeviceList() {
        deviceManager = new PKCS11DeviceManager(pkcs11Mock);
        deviceManager.registerDeviceChangeListener(listenerMock);

        deviceManager.softReset();

        verify(listenerMock, atLeastOnce()).onDeviceConnected(any(PKCS11Device.class));
    }

    @Test
    void close_shouldReleaseResources() {
        deviceManager = new PKCS11DeviceManager(pkcs11Mock);
        deviceManager.close();

        verify(pkcs11Mock, times(1)).C_Finalize(null);
    }



    @Test
    void prepareForDeviceChange_shouldReinitializeDevices() {
        deviceManager = new PKCS11DeviceManager(pkcs11Mock);
        deviceManager.registerDeviceChangeListener(listenerMock);

        deviceManager.prepareForDeviceChange();

        verify(listenerMock, atLeastOnce()).onDeviceConnected(any(PKCS11Device.class));
    }
}
