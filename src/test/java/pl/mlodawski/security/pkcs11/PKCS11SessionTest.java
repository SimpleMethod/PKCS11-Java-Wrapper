package pl.mlodawski.security.pkcs11;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import pl.mlodawski.security.pkcs11.exceptions.SessionCloseException;
import pl.mlodawski.security.pkcs11.exceptions.SessionLoginException;
import pl.mlodawski.security.pkcs11.exceptions.SessionLogoutException;
import pl.mlodawski.security.pkcs11.exceptions.SessionOpenException;
import pl.mlodawski.security.pkcs11.exceptions.SessionResetException;
import pl.mlodawski.security.pkcs11.jna.Cryptoki;
import pl.mlodawski.security.pkcs11.jna.constants.ReturnValue;
import com.sun.jna.NativeLong;
import com.sun.jna.ptr.NativeLongByReference;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class PKCS11SessionTest {

    @Mock
    private Cryptoki pkcs11Mock;

    private PKCS11Session pkcs11Session;
    private String pin;
    private int slotId;

    @BeforeEach
    void setUp() {
        pin = "1234";
        slotId = 1;
    }

    @Test
    void constructor_validParameters_shouldInitializeSuccessfully() {
        when(pkcs11Mock.C_OpenSession(any(NativeLong.class), any(NativeLong.class), isNull(), isNull(), any(NativeLongByReference.class)))
                .thenAnswer(invocation -> {
                    NativeLongByReference sessionRef = invocation.getArgument(4);
                    sessionRef.setValue(new NativeLong(1));
                    return new NativeLong(ReturnValue.OK);
                });

        when(pkcs11Mock.C_Login(any(NativeLong.class), any(NativeLong.class), any(), any(NativeLong.class)))
                .thenReturn(new NativeLong(ReturnValue.OK));

        pkcs11Session = new PKCS11Session(pkcs11Mock, pin, slotId);

        assertNotNull(pkcs11Session.getSession());
        assertEquals(new NativeLong(1), pkcs11Session.getSession());
    }

    @Test
    void constructor_nullPkcs11_shouldThrowIllegalArgumentException() {
        assertThrows(IllegalArgumentException.class, () -> new PKCS11Session(null, pin, slotId));
    }

    @Test
    void constructor_nullPin_shouldThrowIllegalArgumentException() {
        assertThrows(IllegalArgumentException.class, () -> new PKCS11Session(pkcs11Mock, null, slotId));
    }

    @Test
    void openSession_failure_shouldThrowSessionOpenException() {
        when(pkcs11Mock.C_OpenSession(any(NativeLong.class), any(NativeLong.class), isNull(), isNull(), any(NativeLongByReference.class)))
                .thenThrow(new RuntimeException("Session open failed"));

        assertThrows(SessionOpenException.class, () -> new PKCS11Session(pkcs11Mock, pin, slotId));
    }

    @Test
    void login_failure_shouldThrowSessionLoginException() {
        when(pkcs11Mock.C_OpenSession(any(NativeLong.class), any(NativeLong.class), isNull(), isNull(), any(NativeLongByReference.class)))
                .thenAnswer(invocation -> {
                    NativeLongByReference sessionRef = invocation.getArgument(4);
                    sessionRef.setValue(new NativeLong(1));
                    return new NativeLong(ReturnValue.OK);
                });

        when(pkcs11Mock.C_Login(any(NativeLong.class), any(NativeLong.class), any(), any(NativeLong.class)))
                .thenThrow(new RuntimeException("Login failed"));

        assertThrows(SessionLoginException.class, () -> new PKCS11Session(pkcs11Mock, pin, slotId));
    }

    @Test
    void resetSession_shouldLogoutAndLogin() {
        when(pkcs11Mock.C_OpenSession(any(NativeLong.class), any(NativeLong.class), isNull(), isNull(), any(NativeLongByReference.class)))
                .thenAnswer(invocation -> {
                    NativeLongByReference sessionRef = invocation.getArgument(4);
                    sessionRef.setValue(new NativeLong(1));
                    return new NativeLong(ReturnValue.OK);
                });

        when(pkcs11Mock.C_Login(any(NativeLong.class), any(NativeLong.class), any(), any(NativeLong.class)))
                .thenReturn(new NativeLong(ReturnValue.OK));

        pkcs11Session = new PKCS11Session(pkcs11Mock, pin, slotId);

        when(pkcs11Mock.C_Logout(any(NativeLong.class))).thenReturn(new NativeLong(ReturnValue.OK));
        when(pkcs11Mock.C_Login(any(NativeLong.class), any(NativeLong.class), any(), any(NativeLong.class)))
                .thenReturn(new NativeLong(ReturnValue.OK));

        pkcs11Session.resetSession();

        verify(pkcs11Mock, times(2)).C_Login(any(NativeLong.class), any(NativeLong.class), any(), any(NativeLong.class));
        verify(pkcs11Mock, times(1)).C_Logout(any(NativeLong.class));
    }

    @Test
    void resetSession_failure_shouldThrowSessionResetException() {
        when(pkcs11Mock.C_OpenSession(any(NativeLong.class), any(NativeLong.class), isNull(), isNull(), any(NativeLongByReference.class)))
                .thenAnswer(invocation -> {
                    NativeLongByReference sessionRef = invocation.getArgument(4);
                    sessionRef.setValue(new NativeLong(1));
                    return new NativeLong(ReturnValue.OK);
                });

        when(pkcs11Mock.C_Login(any(NativeLong.class), any(NativeLong.class), any(), any(NativeLong.class)))
                .thenReturn(new NativeLong(ReturnValue.OK));

        pkcs11Session = new PKCS11Session(pkcs11Mock, pin, slotId);

        when(pkcs11Mock.C_Logout(any(NativeLong.class))).thenReturn(new NativeLong(ReturnValue.OK));
        when(pkcs11Mock.C_Login(any(NativeLong.class), any(NativeLong.class), any(), any(NativeLong.class)))
                .thenThrow(new RuntimeException("Login failed"));

        assertThrows(SessionResetException.class, () -> pkcs11Session.resetSession());
    }

    @Test
    void logout_shouldCallCLogout() {
        when(pkcs11Mock.C_OpenSession(any(NativeLong.class), any(NativeLong.class), isNull(), isNull(), any(NativeLongByReference.class)))
                .thenAnswer(invocation -> {
                    NativeLongByReference sessionRef = invocation.getArgument(4);
                    sessionRef.setValue(new NativeLong(1));
                    return new NativeLong(ReturnValue.OK);
                });

        when(pkcs11Mock.C_Login(any(NativeLong.class), any(NativeLong.class), any(), any(NativeLong.class)))
                .thenReturn(new NativeLong(ReturnValue.OK));

        pkcs11Session = new PKCS11Session(pkcs11Mock, pin, slotId);

        when(pkcs11Mock.C_Logout(any(NativeLong.class))).thenReturn(new NativeLong(ReturnValue.OK));

        pkcs11Session.logout();

        verify(pkcs11Mock, times(1)).C_Logout(any(NativeLong.class));
    }


    @Test
    void close_failure_shouldThrowSessionCloseException() {
        when(pkcs11Mock.C_OpenSession(any(NativeLong.class), any(NativeLong.class), isNull(), isNull(), any(NativeLongByReference.class)))
                .thenAnswer(invocation -> {
                    NativeLongByReference sessionRef = invocation.getArgument(4);
                    sessionRef.setValue(new NativeLong(1));
                    return new NativeLong(ReturnValue.OK);
                });

        when(pkcs11Mock.C_Login(any(NativeLong.class), any(NativeLong.class), any(), any(NativeLong.class)))
                .thenReturn(new NativeLong(ReturnValue.OK));

        pkcs11Session = new PKCS11Session(pkcs11Mock, pin, slotId);

        when(pkcs11Mock.C_Logout(any(NativeLong.class))).thenThrow(new RuntimeException("Logout failed"));

        assertThrows(SessionCloseException.class, () -> pkcs11Session.close());
    }
}
