package pl.mlodawski.security.pkcs11;


import lombok.Getter;
import lombok.extern.slf4j.Slf4j;
import pl.mlodawski.security.pkcs11.exceptions.*;
import pl.mlodawski.security.pkcs11.jna.Cryptoki;
import pl.mlodawski.security.pkcs11.jna.constants.ReturnValue;
import pl.mlodawski.security.pkcs11.jna.constants.SessionFlags;
import pl.mlodawski.security.pkcs11.jna.constants.UserType;
import com.sun.jna.NativeLong;
import com.sun.jna.ptr.NativeLongByReference;

@Slf4j
public class PKCS11Session implements AutoCloseable {
    private final Cryptoki pkcs11;
    @Getter
    private final NativeLong session;
    private final String pin;
    private volatile boolean isLoggedIn;
    private volatile boolean isSessionOpen;

    public PKCS11Session(Cryptoki pkcs11, String pin, int slotId) {
        if (pkcs11 == null) {
            throw new IllegalArgumentException("pkcs11 cannot be null");
        }
        if (pin == null) {
            throw new IllegalArgumentException("pin cannot be null");
        }
        this.pkcs11 = pkcs11;
        this.pin = pin;
        this.isLoggedIn = false;
        this.isSessionOpen = false;
        this.session = openSession(slotId);
        this.isSessionOpen = true;
        login();
    }

    /**
     * Opens a PKCS11 session for the specified slot ID.
     *
     * @param slotId the slot ID of the token
     * @return the session ID of the opened session
     * @throws SessionOpenException if an error occurs while opening the session
     */
    private NativeLong openSession(int slotId) {
        try {
            NativeLongByReference sessionRef = new NativeLongByReference();
            NativeLong rv = pkcs11.C_OpenSession(
                    new NativeLong(slotId),
                    new NativeLong(SessionFlags.SERIAL_SESSION | SessionFlags.RW_SESSION),
                    null,
                    null,
                    sessionRef
            );

            if (!ReturnValue.isSuccess(rv)) {
                throw new SessionOpenException("Failed to open session, error: " + rv.longValue(),null);
            }

            NativeLong sessionHandle = sessionRef.getValue();
            if (sessionHandle == null) {
                throw new SessionOpenException("Received null session handle",null);
            }

            return sessionHandle;
        } catch (Exception e) {
            log.error("Error opening session for slot {}", slotId, e);
            throw new SessionOpenException("Failed to open session", e);
        }
    }

    /**
     * Logs the user into the session using the provided PIN.
     *
     * This method first checks if the session is open. If the session is not open,
     * it throws a SessionLoginException.
     *
     * The method attempts to log in using the PKCS#11 C_Login function.
     * If the login attempt fails or the user is already logged in, it throws a SessionLoginException.
     *
     * If an unexpected exception occurs during the login process, an error is logged,
     * and a SessionLoginException is thrown.
     *
     * This method sets the isLoggedIn flag to true if the login is successful.
     *
     * @throws SessionLoginException if the session is not open, if login fails,
     *                               or if an internal error occurs during login.
     */
    private void login() {
        if (!isSessionOpen) {
            throw new SessionLoginException("Cannot login: session is not open",null);
        }

        try {
            NativeLong rv = pkcs11.C_Login(session, new NativeLong(UserType.USER),
                    pin.getBytes(), new NativeLong(pin.length()));

            if (!ReturnValue.isSuccess(rv) &&
                    rv.longValue() != ReturnValue.USER_ALREADY_LOGGED_IN) {
                throw new SessionLoginException("Failed to login, error: " + rv.longValue(),null);
            }

            isLoggedIn = true;
        } catch (Exception e) {
            log.error("Error logging in", e);
            isLoggedIn = false;
            throw new SessionLoginException("Failed to login", e);
        }
    }

    /**
     * Logs out the current user if they are logged in and a session is open.
     * The method attempts to log out using the PKCS#11 C_Logout function.
     * If an error occurs during the logout process, it logs a warning for unexpected
     * return codes and an error for exceptions.
     * Upon successful logout or failure, updates the state to indicate that
     * the user is no longer logged in.
     */
    public void logout() {
        if (!isLoggedIn || !isSessionOpen) {
            return;
        }

        try {
            NativeLong rv = pkcs11.C_Logout(session);
            if (!ReturnValue.isSuccess(rv) &&
                    rv.longValue() != ReturnValue.USER_NOT_LOGGED_IN) {
                log.warn("Logout returned unexpected code: {}", rv.longValue());
            }
        } catch (Exception e) {
            log.error("Error during logout", e);
        } finally {
            isLoggedIn = false;
        }
    }

    /**
     * Resets the current session by performing a logout followed by a login.
     *
     * This method first checks if the session is open. If the session is not open, it throws
     * a SessionResetException. If the session is open, it attempts to logout and then login
     * again. Any exception during this process is caught, logged, and then wrapped in a
     * SessionResetException which is then thrown.
     *
     * @throws SessionResetException if the session*/
    public void resetSession() {
        if (!isSessionOpen) {
            throw new SessionResetException("Cannot reset: session is not open",null);
        }

        try {
            logout();
            login();
        } catch (Exception e) {
            log.error("Error resetting session", e);
            throw new SessionResetException("Failed to reset session", e);
        }
    }

    /**
     * Closes the current PKCS#11 session if it is open.
     *
     * This method first checks whether the session is open. If not, it returns immediately.
     * If the session is open, it attempts to log out and then close the session using the PKCS#11 library.
     * It handles exceptions during the session close process and logs any errors encountered.
     * Finally, it updates the internal state to indicate that the session is no longer open and the user is logged out.
     *
     * @throws SessionCloseException if an error occurs while closing the session.
     */
    @Override
    public void close() {
        if (!isSessionOpen) {
            return;
        }

        try {
            logout();
            NativeLong rv = pkcs11.C_CloseSession(session);
            if (!ReturnValue.isSuccess(rv) &&
                    rv.longValue() != ReturnValue.SESSION_HANDLE_INVALID) {
                throw new SessionCloseException("Failed to close session, error: " + rv.longValue(),null);
            }
        } catch (Exception e) {
            if (e instanceof SessionCloseException) {
                throw e;
            }
            log.error("Error closing session", e);
            throw new SessionCloseException("Failed to close session", e);
        } finally {
            isSessionOpen = false;
            isLoggedIn = false;
        }
    }

    /**
     * Determines if a user is logged in and the session is currently open.
     *
     * @return true if the user is logged in and the session is open; false otherwise.
     */
    public boolean isLoggedIn() {
        return isLoggedIn && isSessionOpen;
    }

    /**
     * Checks if the session is currently open.
     *
     * @return true if the session is open, false otherwise.
     */
    public boolean isSessionOpen() {
        return isSessionOpen;
    }
}