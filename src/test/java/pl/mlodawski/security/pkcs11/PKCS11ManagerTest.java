package pl.mlodawski.security.pkcs11;


import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.MockedStatic;
import org.mockito.junit.jupiter.MockitoExtension;
import pl.mlodawski.security.pkcs11.exceptions.PKCS11FinalizationException;
import pl.mlodawski.security.pkcs11.exceptions.PKCS11InitializationException;
import pl.mlodawski.security.pkcs11.model.PKCS11Device;
import pl.mlodawski.security.pkcs11.jna.Cryptoki;
import pl.mlodawski.security.pkcs11.jna.constants.ReturnValue;
import pl.mlodawski.security.pkcs11.jna.structure.SlotInfo;
import pl.mlodawski.security.pkcs11.jna.structure.TokenInfo;

import java.nio.file.Path;
import java.util.List;
import java.util.Optional;
import com.sun.jna.NativeLong;
import com.sun.jna.ptr.NativeLongByReference;
import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class PKCS11ManagerTest {

    @Mock
    private Cryptoki pkcs11Mock;

    private Path libraryPathMock;
    private PKCS11Manager pkcs11Manager;

    @BeforeEach
    void setUp() {
        libraryPathMock = mock(Path.class);

        when(pkcs11Mock.C_GetSlotList(anyByte(), any(), any(NativeLongByReference.class)))
                .thenAnswer(invocation -> {
                    NativeLongByReference count = invocation.getArgument(2);
                    count.setValue(new NativeLong(1));
                    return new NativeLong(ReturnValue.OK);
                });

        when(pkcs11Mock.C_GetSlotList(anyByte(), any(NativeLong[].class), any(NativeLongByReference.class)))
                .thenAnswer(invocation -> {
                    NativeLong[] slots = invocation.getArgument(1);
                    slots[0] = new NativeLong(0);
                    return new NativeLong(ReturnValue.OK);
                });

        when(pkcs11Mock.C_GetSlotInfo(any(NativeLong.class), any(SlotInfo.class)))
                .thenReturn(new NativeLong(ReturnValue.OK));

        when(pkcs11Mock.C_GetTokenInfo(any(NativeLong.class), any(TokenInfo.class)))
                .thenReturn(new NativeLong(ReturnValue.OK));
    }

    @Test
    void constructor_validParameters_shouldInitializeSuccessfully() {
        try (MockedStatic<PKCS11Initializer> mockedInitializer = mockStatic(PKCS11Initializer.class)) {
            mockedInitializer.when(() -> PKCS11Initializer.initializePkcs11(any(Path.class)))
                    .thenReturn(pkcs11Mock);

            pkcs11Manager = new PKCS11Manager(libraryPathMock);

            assertNotNull(pkcs11Manager.getPkcs11());
            assertEquals(pkcs11Mock, pkcs11Manager.getPkcs11());
        }
    }



    @Test
    void listDevices_shouldReturnDeviceList() {
        try (MockedStatic<PKCS11Initializer> mockedInitializer = mockStatic(PKCS11Initializer.class)) {
            mockedInitializer.when(() -> PKCS11Initializer.initializePkcs11(any(Path.class)))
                    .thenReturn(pkcs11Mock);

            pkcs11Manager = new PKCS11Manager(libraryPathMock);
            List<PKCS11Device> devices = pkcs11Manager.listDevices();

            assertNotNull(devices);
            assertFalse(devices.isEmpty());
        }
    }

    @Test
    void getDevice_existingDevice_shouldReturnDevice() {
        try (MockedStatic<PKCS11Initializer> mockedInitializer = mockStatic(PKCS11Initializer.class)) {
            mockedInitializer.when(() -> PKCS11Initializer.initializePkcs11(any(Path.class)))
                    .thenReturn(pkcs11Mock);

            pkcs11Manager = new PKCS11Manager(libraryPathMock);
            Optional<PKCS11Device> device = pkcs11Manager.getDevice(new NativeLong(0));

            assertTrue(device.isPresent());
        }
    }

    @Test
    void openSession_nullDevice_shouldThrowIllegalArgumentException() {
        try (MockedStatic<PKCS11Initializer> mockedInitializer = mockStatic(PKCS11Initializer.class)) {
            mockedInitializer.when(() -> PKCS11Initializer.initializePkcs11(any(Path.class)))
                    .thenReturn(pkcs11Mock);

            pkcs11Manager = new PKCS11Manager(libraryPathMock);
            assertThrows(IllegalArgumentException.class, () -> pkcs11Manager.openSession(null, "1234"));
        }
    }

    @Test
    void close_finalizationFailure_shouldThrowPKCS11FinalizationException() {
        try (MockedStatic<PKCS11Initializer> mockedInitializer = mockStatic(PKCS11Initializer.class)) {
            mockedInitializer.when(() -> PKCS11Initializer.initializePkcs11(any(Path.class)))
                    .thenReturn(pkcs11Mock);

            doThrow(new RuntimeException("Finalization failed"))
                    .when(pkcs11Mock).C_Finalize(null);

            pkcs11Manager = new PKCS11Manager(libraryPathMock);

            assertThrows(PKCS11FinalizationException.class, () -> pkcs11Manager.close());
        }
    }
}