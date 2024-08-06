package pl.mlodawski.security.pkcs11;


import lombok.Getter;
import lombok.extern.slf4j.Slf4j;
import pl.mlodawski.security.pkcs11.exceptions.*;
import ru.rutoken.pkcs11jna.Pkcs11;
import ru.rutoken.pkcs11jna.Pkcs11Constants;
import com.sun.jna.NativeLong;
import com.sun.jna.ptr.NativeLongByReference;

@Slf4j
public class PKCS11Session implements AutoCloseable {
    private final Pkcs11 pkcs11;
    @Getter
    private final NativeLong session;
    private final String pin;

    /**
     * Constructs a PKCS11 Session object for the specified PKCS11 instance, PIN, and slot ID.
     *
     * @param pkcs11   the PKCS11 instance to use
     * @param pin      the PIN used for authentication
     * @param slotId   the slot ID of the token
     * @throws IllegalArgumentException if pkcs11 is null or pin is null
     * @throws RuntimeException         if an error occurs while opening the session
     */
    public PKCS11Session(Pkcs11 pkcs11, String pin, int slotId) {
        if (pkcs11 == null) {
            throw new IllegalArgumentException("pkcs11 cannot be null");
        }
        if (pin == null) {
            throw new IllegalArgumentException("pin cannot be null");
        }
        this.pkcs11 = pkcs11;
        this.pin = pin;
        this.session = openSession(slotId);
        login();
    }

    /**
     * Opens a PKCS11 session for the specified slot ID.
     *
     * @param slotId the slot ID of the token
     * @return the session ID of the opened session
     * @throws RuntimeException if an error occurs while opening the session
     */
    private NativeLong openSession(int slotId) {
        try {
            NativeLongByReference sessionRef = new NativeLongByReference();
            pkcs11.C_OpenSession(new NativeLong(slotId), new NativeLong(Pkcs11Constants.CKF_SERIAL_SESSION | Pkcs11Constants.CKF_RW_SESSION), null, null, sessionRef);
            return sessionRef.getValue();
        } catch (Exception e) {
            log.error("Error opening session", e);
            throw new SessionOpenException("Failed to open session", e);
        }
    }

    /**
     * This method is used to log in to a PKCS11 session.
     * It performs the login operation using the provided PIN.
     *
     * @throws RuntimeException if an error occurs while logging in
     */
    private void login() {
        try {
            pkcs11.C_Login(session, new NativeLong(Pkcs11Constants.CKU_USER), pin.getBytes(), new NativeLong(pin.length()));
        } catch (Exception e) {
            log.error("Error logging in", e);
            throw new SessionLoginException("Failed to login", e);
        }
    }

    /**
     * Resets the session by logging out and logging back in.
     *
     * This method calls the C_Logout method to log out of the current session,
     * and then calls the login() method to log back in using the provided PIN.
     *
     * @throws RuntimeException if an error occurs while resetting the session
     */
    public void resetSession() {
        try {
            pkcs11.C_Logout(session);
            login();
        } catch (Exception e) {
            log.error("Error resetting session", e);
            throw new SessionResetException("Failed to reset session", e);
        }
    }


    /**
     * Executes the logout operation on the PKCS11 session.
     * This method logs out the user from the PKCS11 session.
     * If an error occurs during the logout operation, an error message
     * is logged and a RuntimeException is thrown.
     *
     * @throws RuntimeException if an error occurs during logout
     */
    public void logout() {
        try {
            pkcs11.C_Logout(session);
        } catch (Exception e) {
            log.error("Error logging out", e);
            throw new SessionLogoutException("Failed to logout", e);
        }
    }

    /**
     * Closes the PKCS#11 session.
     *
     * This method logs out from the session, closes the session, and finalizes the PKCS#11 library.
     *
     * @throws RuntimeException if an error occurs while closing the session
     */
    @Override
    public void close() {
        try {
            pkcs11.C_Logout(session);
            pkcs11.C_CloseSession(session);
            pkcs11.C_Finalize(null);
        } catch (Exception e) {
            log.error("Error closing session", e);
            throw new SessionCloseException("Failed to close session", e);
        }
    }
}