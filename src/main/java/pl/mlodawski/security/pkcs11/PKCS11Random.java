package pl.mlodawski.security.pkcs11;

import com.sun.jna.NativeLong;
import lombok.extern.slf4j.Slf4j;
import pl.mlodawski.security.pkcs11.exceptions.RandomGenerationException;
import pl.mlodawski.security.pkcs11.jna.Cryptoki;
import pl.mlodawski.security.pkcs11.jna.constants.ReturnValue;

import java.security.SecureRandom;

/**
 * Provides hardware-based random number generation using PKCS#11 tokens.
 * Uses C_GenerateRandom from the PKCS#11 specification for cryptographically
 * secure random data generation on hardware security modules.
 */
@Slf4j
public class PKCS11Random extends SecureRandom {

    private final Cryptoki pkcs11;
    private final NativeLong session;

    /**
     * Creates a new PKCS11Random instance.
     *
     * @param pkcs11  the PKCS#11 interface instance
     * @param session the session handle
     * @throws IllegalArgumentException if pkcs11 or session is null
     */
    public PKCS11Random(Cryptoki pkcs11, NativeLong session) {
        if (pkcs11 == null) {
            throw new IllegalArgumentException("pkcs11 cannot be null");
        }
        if (session == null) {
            throw new IllegalArgumentException("session cannot be null");
        }
        this.pkcs11 = pkcs11;
        this.session = session;
    }

    /**
     * Generates random bytes using the hardware token.
     *
     * @param bytes the byte array to fill with random data
     * @throws RandomGenerationException if an error occurs during random generation
     */
    @Override
    public void nextBytes(byte[] bytes) {
        if (bytes == null) {
            throw new IllegalArgumentException("bytes cannot be null");
        }
        if (bytes.length == 0) {
            return;
        }

        try {
            NativeLong rv = pkcs11.C_GenerateRandom(session, bytes, new NativeLong(bytes.length));
            if (!ReturnValue.isSuccess(rv)) {
                throw new RandomGenerationException(
                        "C_GenerateRandom failed with error code: 0x" + Long.toHexString(rv.longValue()), null);
            }
            log.debug("Generated {} random bytes using hardware RNG", bytes.length);
        } catch (RandomGenerationException e) {
            throw e;
        } catch (Exception e) {
            log.error("Error generating random bytes", e);
            throw new RandomGenerationException("Error generating random bytes", e);
        }
    }

    /**
     * Generates a specified number of random bytes.
     *
     * @param numBytes the number of random bytes to generate
     * @return byte array containing random data
     * @throws IllegalArgumentException  if numBytes is negative
     * @throws RandomGenerationException if an error occurs during random generation
     */
    public byte[] generateRandomBytes(int numBytes) {
        if (numBytes < 0) {
            throw new IllegalArgumentException("numBytes cannot be negative");
        }
        if (numBytes == 0) {
            return new byte[0];
        }

        byte[] randomBytes = new byte[numBytes];
        nextBytes(randomBytes);
        return randomBytes;
    }

    /**
     * Generates a random integer using hardware RNG.
     *
     * @return a random integer
     */
    @Override
    public int nextInt() {
        byte[] bytes = new byte[4];
        nextBytes(bytes);
        return ((bytes[0] & 0xFF) << 24) |
                ((bytes[1] & 0xFF) << 16) |
                ((bytes[2] & 0xFF) << 8) |
                (bytes[3] & 0xFF);
    }

    /**
     * Generates a random long using hardware RNG.
     *
     * @return a random long
     */
    @Override
    public long nextLong() {
        byte[] bytes = new byte[8];
        nextBytes(bytes);
        return ((long) (bytes[0] & 0xFF) << 56) |
                ((long) (bytes[1] & 0xFF) << 48) |
                ((long) (bytes[2] & 0xFF) << 40) |
                ((long) (bytes[3] & 0xFF) << 32) |
                ((long) (bytes[4] & 0xFF) << 24) |
                ((long) (bytes[5] & 0xFF) << 16) |
                ((long) (bytes[6] & 0xFF) << 8) |
                ((long) (bytes[7] & 0xFF));
    }

    /**
     * Generates a random boolean using hardware RNG.
     *
     * @return a random boolean
     */
    @Override
    public boolean nextBoolean() {
        byte[] bytes = new byte[1];
        nextBytes(bytes);
        return (bytes[0] & 0x01) != 0;
    }

    /**
     * Generates a random double between 0.0 (inclusive) and 1.0 (exclusive).
     *
     * @return a random double
     */
    @Override
    public double nextDouble() {
        return (nextLong() >>> 11) * 0x1.0p-53;
    }

    /**
     * Generates a random float between 0.0 (inclusive) and 1.0 (exclusive).
     *
     * @return a random float
     */
    @Override
    public float nextFloat() {
        return (nextInt() >>> 8) * 0x1.0p-24f;
    }

    @Override
    public String getAlgorithm() {
        return "PKCS11-HardwareRNG";
    }
}
