package pl.mlodawski.security.pkcs11;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.MockedStatic;
import org.mockito.junit.jupiter.MockitoExtension;
import pl.mlodawski.security.pkcs11.exceptions.PKCS11FinalizationException;
import pl.mlodawski.security.pkcs11.exceptions.PKCS11InitializationException;
import ru.rutoken.pkcs11jna.Pkcs11;
import eu.europa.esig.dss.token.Pkcs11SignatureToken;

import java.nio.file.Path;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class PKCS11ManagerTest {

    @Mock
    private Pkcs11 pkcs11Mock;

    private Path libraryPathMock;
    private String pin;
    private PKCS11Manager pkcs11Manager;

    @BeforeEach
    void setUp() {
        libraryPathMock = mock(Path.class);
        pin = "1234";
    }

    @Test
    void constructor_validParameters_shouldInitializeSuccessfully() {
        try (MockedStatic<PKCS11Initializer> mockedInitializer = mockStatic(PKCS11Initializer.class)) {
            mockedInitializer.when(() -> PKCS11Initializer.initializePkcs11(any(Path.class)))
                    .thenReturn(pkcs11Mock);

            pkcs11Manager = new PKCS11Manager(libraryPathMock, pin);

            assertNotNull(pkcs11Manager.getPkcs11());
            assertEquals(pkcs11Mock, pkcs11Manager.getPkcs11());
        }
    }

    @Test
    void constructor_nullLibraryPath_shouldThrowIllegalArgumentException() {
        assertThrows(IllegalArgumentException.class, () -> new PKCS11Manager(null, pin));
    }

    @Test
    void constructor_nullPin_shouldThrowIllegalArgumentException() {
        assertThrows(IllegalArgumentException.class, () -> new PKCS11Manager(libraryPathMock, null));
    }

    @Test
    void constructor_emptyPin_shouldThrowIllegalArgumentException() {
        assertThrows(IllegalArgumentException.class, () -> new PKCS11Manager(libraryPathMock, ""));
    }

    @Test
    void constructor_initializationFailure_shouldThrowPKCS11InitializationException() {
        try (MockedStatic<PKCS11Initializer> mockedInitializer = mockStatic(PKCS11Initializer.class)) {
            mockedInitializer.when(() -> PKCS11Initializer.initializePkcs11(any(Path.class)))
                    .thenThrow(new PKCS11InitializationException("Initialization failed", null));

            assertThrows(PKCS11InitializationException.class, () -> new PKCS11Manager(libraryPathMock, pin));
        }
    }

    @Test
    void getPKCS11Token_shouldReturnPkcs11SignatureToken() {
        try (MockedStatic<PKCS11Initializer> mockedInitializer = mockStatic(PKCS11Initializer.class)) {
            mockedInitializer.when(() -> PKCS11Initializer.initializePkcs11(any(Path.class)))
                    .thenReturn(pkcs11Mock);

            pkcs11Manager = new PKCS11Manager(libraryPathMock, pin);
            Pkcs11SignatureToken token = pkcs11Manager.getPKCS11Token();

            assertNotNull(token);
        }
    }

    @Test
    void close_shouldFinalizePkcs11() {
        try (MockedStatic<PKCS11Initializer> mockedInitializer = mockStatic(PKCS11Initializer.class)) {
            mockedInitializer.when(() -> PKCS11Initializer.initializePkcs11(any(Path.class)))
                    .thenReturn(pkcs11Mock);

            pkcs11Manager = new PKCS11Manager(libraryPathMock, pin);
            pkcs11Manager.close();

            verify(pkcs11Mock, times(1)).C_Finalize(null);
        }
    }

    @Test
    void close_finalizationFailure_shouldThrowPKCS11FinalizationException() {
        try (MockedStatic<PKCS11Initializer> mockedInitializer = mockStatic(PKCS11Initializer.class)) {
            mockedInitializer.when(() -> PKCS11Initializer.initializePkcs11(any(Path.class)))
                    .thenReturn(pkcs11Mock);

            doThrow(new RuntimeException("Finalization failed")).when(pkcs11Mock).C_Finalize(null);

            pkcs11Manager = new PKCS11Manager(libraryPathMock, pin);

            assertThrows(PKCS11FinalizationException.class, () -> pkcs11Manager.close());
        }
    }
}
