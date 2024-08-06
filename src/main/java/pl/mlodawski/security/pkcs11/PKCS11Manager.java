package pl.mlodawski.security.pkcs11;

import lombok.Getter;
import pl.mlodawski.security.pkcs11.exceptions.PKCS11FinalizationException;
import pl.mlodawski.security.pkcs11.exceptions.PKCS11InitializationException;
import ru.rutoken.pkcs11jna.Pkcs11;

import eu.europa.esig.dss.token.Pkcs11SignatureToken;
import lombok.extern.slf4j.Slf4j;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

import java.nio.file.Path;
import java.security.Security;

@Slf4j
public class PKCS11Manager implements AutoCloseable {
    @Getter
    private final Pkcs11 pkcs11;
    private final Path libraryPath;
    private final String pin;

    /**
     * Initializes a PKCS11Manager with the specified library path and PIN.
     *
     * @param libraryPath the path of the PKCS#11 library file
     * @param pin the PIN used for authentication
     * @throws IllegalArgumentException if libraryPath is null or pin is null or empty
     * @throws RuntimeException if PKCS#11 initialization fails
     */
    public PKCS11Manager(Path libraryPath, String pin) {
        if (libraryPath == null) {
            throw new IllegalArgumentException("libraryPath cannot be null");
        }
        if (pin == null || pin.isEmpty()) {
            throw new IllegalArgumentException("pin cannot be null or empty");
        }

        Security.addProvider(new BouncyCastleProvider());
        this.libraryPath = libraryPath;
        this.pin = pin;

        try {
            this.pkcs11 = PKCS11Initializer.initializePkcs11(libraryPath);
        } catch (Exception e) {
            log.error("PKCS#11 initialization failed", e);
            throw new PKCS11InitializationException("PKCS#11 initialization failed", e);
        }
    }

    /**
     * Opens a PKCS11Session for the specified slot ID.
     *
     * @param slotId the slot ID of the token
     * @return a PKCS11Session object representing the opened session
     * @throws RuntimeException if an error occurs while opening the session
     */
    public PKCS11Session openSession(int slotId) {
        return new PKCS11Session(pkcs11, pin, slotId);
    }

    /**
     * Retrieves the PKCS#11 signature token.
     *
     * @return a Pkcs11SignatureToken object representing the PKCS#11 signature token
     */
    public Pkcs11SignatureToken getPKCS11Token() {
        return new Pkcs11SignatureToken(libraryPath.toString(), pin::toCharArray);
    }

    /**
     * Closes the PKCS11Manager by finalizing the PKCS#11 library.
     * The C_Finalize method is called to perform the finalization.
     * If an exception occurs during the finalization process, an error message is logged and a RuntimeException is thrown.
     *
     * @throws RuntimeException if an error occurs while finalizing the PKCS#11 library
     */
    @Override
    public void close() {
        try {
            pkcs11.C_Finalize(null);
        } catch (Exception e) {
            log.error("Failed to finalize PKCS#11", e);
            throw new PKCS11FinalizationException("Failed to finalize PKCS#11", e);
        }
    }
}
