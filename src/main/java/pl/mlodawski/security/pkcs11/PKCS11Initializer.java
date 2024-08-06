package pl.mlodawski.security.pkcs11;

import lombok.extern.slf4j.Slf4j;
import pl.mlodawski.security.pkcs11.exceptions.PKCS11InitializationException;
import ru.rutoken.pkcs11jna.*;
import com.sun.jna.NativeLong;
import com.sun.jna.Native;

import java.nio.file.Path;

@Slf4j
public class PKCS11Initializer {

    /**
     * Initializes the PKCS#11 library with the specified library path.
     *
     * @param libraryPath the path of the PKCS#11 library file
     * @return a Pkcs11 object representing the initialized PKCS#11 library
     * @throws IllegalArgumentException if libraryPath is null
     * @throws RuntimeException         if PKCS#11 initialization fails
     */
    public static Pkcs11 initializePkcs11(Path libraryPath) {
        if (libraryPath == null) {
            throw new IllegalArgumentException("libraryPath cannot be null");
        }

        try {
            CK_C_INITIALIZE_ARGS initArgs = new CK_C_INITIALIZE_ARGS();
            initArgs.flags = new NativeLong(0);
            initArgs.pReserved = null;

            Pkcs11 pkcs11 = Native.load(libraryPath.toString(), Pkcs11.class);
            NativeLong rv = pkcs11.C_Initialize(initArgs);
            if (rv.longValue() != Pkcs11Constants.CKR_OK) {
                throw new RuntimeException("Failed to initialize PKCS#11 library. Error: " + rv.longValue());
            }
            return pkcs11;
        } catch (Exception e) {
            log.error("PKCS#11 initialization failed", e);
            throw new PKCS11InitializationException("PKCS#11 initialization failed", e);
        }
    }
}
