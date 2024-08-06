package pl.mlodawski.security.pkcs11;

import com.sun.jna.Native;
import com.sun.jna.NativeLong;
import org.junit.jupiter.api.Test;
import org.mockito.MockedStatic;
import org.mockito.Mockito;
import pl.mlodawski.security.pkcs11.exceptions.PKCS11InitializationException;
import ru.rutoken.pkcs11jna.Pkcs11;
import ru.rutoken.pkcs11jna.Pkcs11Constants;

import java.nio.file.Path;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;


class PKCS11InitializerTest {


    @Test
    void initializePkcs11_nullPath_shouldThrowIllegalArgumentException() {
        assertThrows(IllegalArgumentException.class, () -> PKCS11Initializer.initializePkcs11(null));
    }

    @Test
    void initializePkcs11_initializationFailure_shouldThrowPKCS11InitializationException() {
        // Mock the library path and Pkcs11 class
        Path libraryPathMock = mock(Path.class);
        Pkcs11 pkcs11Mock = mock(Pkcs11.class);

        // Mock behavior of Native.load
        when(libraryPathMock.toString()).thenReturn("mocked/path/to/library");
        try (MockedStatic<Native> mockedNative = Mockito.mockStatic(Native.class)) {
            mockedNative.when(() -> Native.load(anyString(), eq(Pkcs11.class))).thenReturn(pkcs11Mock);
            when(pkcs11Mock.C_Initialize(any())).thenReturn(new NativeLong(Pkcs11Constants.CKR_GENERAL_ERROR));

            assertThrows(PKCS11InitializationException.class, () -> PKCS11Initializer.initializePkcs11(libraryPathMock));
        }
    }

    @Test
    void initializePkcs11_nativeLoadFailure_shouldThrowPKCS11InitializationException() {
        // Mock the library path
        Path libraryPathMock = mock(Path.class);

        // Mock behavior of Native.load to throw an exception
        when(libraryPathMock.toString()).thenReturn("mocked/path/to/library");
        try (MockedStatic<Native> mockedNative = Mockito.mockStatic(Native.class)) {
            mockedNative.when(() -> Native.load(anyString(), eq(Pkcs11.class))).thenThrow(new RuntimeException("Native load failed"));

            assertThrows(PKCS11InitializationException.class, () -> PKCS11Initializer.initializePkcs11(libraryPathMock));
        }
    }
}
