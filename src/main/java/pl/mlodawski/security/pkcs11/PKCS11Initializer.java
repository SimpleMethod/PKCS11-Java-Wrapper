package pl.mlodawski.security.pkcs11;

import lombok.extern.slf4j.Slf4j;
import pl.mlodawski.security.pkcs11.exceptions.PKCS11InitializationException;
import pl.mlodawski.security.pkcs11.jna.Cryptoki;
import pl.mlodawski.security.pkcs11.jna.constants.ReturnValue;
import pl.mlodawski.security.pkcs11.jna.structure.InitializeArgs;
import com.sun.jna.NativeLong;

import java.nio.file.Path;

@Slf4j
public class PKCS11Initializer {

    /**
     * Initializes the PKCS#11 library with the specified library path.
     *
     * @param libraryPath the path of the PKCS#11 library file
     * @return a Cryptoki object representing the initialized PKCS#11 library
     * @throws IllegalArgumentException if libraryPath is null
     * @throws RuntimeException         if PKCS#11 initialization fails
     */
    public static Cryptoki initializePkcs11(Path libraryPath) {
        if (libraryPath == null) {
            throw new IllegalArgumentException("libraryPath cannot be null");
        }

        try {
            InitializeArgs initArgs = new InitializeArgs();
            initArgs.flags = new NativeLong(0);
            initArgs.pReserved = null;

            Cryptoki pkcs11 = Cryptoki.loadLibrary(libraryPath.toString());
            NativeLong rv = pkcs11.C_Initialize(initArgs);
            if (!ReturnValue.isSuccess(rv)) {
                throw new RuntimeException("Failed to initialize PKCS#11 library. Error: " + rv.longValue());
            }
            return pkcs11;
        } catch (Throwable e) {
            log.error("PKCS#11 initialization failed", e);
            throw new PKCS11InitializationException("PKCS#11 initialization failed", e);
        }
    }
}
