package pl.mlodawski.security.pkcs11;

import com.sun.jna.NativeLong;
import com.sun.jna.ptr.NativeLongByReference;
import lombok.extern.slf4j.Slf4j;
import pl.mlodawski.security.pkcs11.exceptions.DigestException;
import pl.mlodawski.security.pkcs11.jna.Cryptoki;
import pl.mlodawski.security.pkcs11.jna.constants.MechanismType;
import pl.mlodawski.security.pkcs11.jna.constants.ReturnValue;
import pl.mlodawski.security.pkcs11.jna.structure.Mechanism;

import java.util.HashMap;
import java.util.Map;

/**
 * Provides hardware-based cryptographic digest (hash) operations using PKCS#11 tokens.
 * Supports multiple hash algorithms including SHA-1, SHA-256, SHA-384, SHA-512, MD5, and RIPEMD160.
 */
@Slf4j
public class PKCS11Digest {

    /**
     * Supported digest algorithms with their PKCS#11 mechanism types and output lengths.
     */
    public enum Algorithm {
        MD5(MechanismType.MD5, 16),
        SHA1(MechanismType.SHA_1, 20),
        SHA224(MechanismType.SHA224, 28),
        SHA256(MechanismType.SHA256, 32),
        SHA384(MechanismType.SHA384, 48),
        SHA512(MechanismType.SHA512, 64),
        RIPEMD160(MechanismType.RIPEMD160, 20);

        private final long mechanismType;
        private final int digestLength;

        Algorithm(long mechanismType, int digestLength) {
            this.mechanismType = mechanismType;
            this.digestLength = digestLength;
        }

        public long getMechanismType() {
            return mechanismType;
        }

        public int getDigestLength() {
            return digestLength;
        }
    }

    private static final Map<String, Algorithm> ALGORITHM_MAP = new HashMap<>();

    static {
        ALGORITHM_MAP.put("MD5", Algorithm.MD5);
        ALGORITHM_MAP.put("SHA-1", Algorithm.SHA1);
        ALGORITHM_MAP.put("SHA1", Algorithm.SHA1);
        ALGORITHM_MAP.put("SHA-224", Algorithm.SHA224);
        ALGORITHM_MAP.put("SHA224", Algorithm.SHA224);
        ALGORITHM_MAP.put("SHA-256", Algorithm.SHA256);
        ALGORITHM_MAP.put("SHA256", Algorithm.SHA256);
        ALGORITHM_MAP.put("SHA-384", Algorithm.SHA384);
        ALGORITHM_MAP.put("SHA384", Algorithm.SHA384);
        ALGORITHM_MAP.put("SHA-512", Algorithm.SHA512);
        ALGORITHM_MAP.put("SHA512", Algorithm.SHA512);
        ALGORITHM_MAP.put("RIPEMD160", Algorithm.RIPEMD160);
        ALGORITHM_MAP.put("RIPEMD-160", Algorithm.RIPEMD160);
    }

    private final Cryptoki pkcs11;
    private final NativeLong session;

    /**
     * Creates a new PKCS11Digest instance.
     *
     * @param pkcs11  the PKCS#11 interface instance
     * @param session the session handle
     * @throws IllegalArgumentException if pkcs11 or session is null
     */
    public PKCS11Digest(Cryptoki pkcs11, NativeLong session) {
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
     * Computes the digest (hash) of the given data using the specified algorithm.
     *
     * @param algorithm the hash algorithm to use
     * @param data      the data to hash
     * @return the computed digest
     * @throws IllegalArgumentException if algorithm or data is null
     * @throws DigestException          if an error occurs during hashing
     */
    public byte[] digest(Algorithm algorithm, byte[] data) {
        if (algorithm == null) {
            throw new IllegalArgumentException("algorithm cannot be null");
        }
        if (data == null) {
            throw new IllegalArgumentException("data cannot be null");
        }

        try {
            Mechanism mechanism = new Mechanism(algorithm.getMechanismType());
            NativeLong rv = pkcs11.C_DigestInit(session, mechanism);
            if (!ReturnValue.isSuccess(rv)) {
                throw new DigestException(
                        "C_DigestInit failed with error code: 0x" + Long.toHexString(rv.longValue()), null);
            }

            NativeLongByReference digestLen = new NativeLongByReference(new NativeLong(0));
            rv = pkcs11.C_Digest(session, data, new NativeLong(data.length), null, digestLen);
            if (!ReturnValue.isSuccess(rv)) {
                throw new DigestException(
                        "C_Digest (get length) failed with error code: 0x" + Long.toHexString(rv.longValue()), null);
            }

            byte[] digest = new byte[digestLen.getValue().intValue()];
            rv = pkcs11.C_Digest(session, data, new NativeLong(data.length), digest, digestLen);
            if (!ReturnValue.isSuccess(rv)) {
                throw new DigestException(
                        "C_Digest failed with error code: 0x" + Long.toHexString(rv.longValue()), null);
            }

            log.debug("Computed {} digest ({} bytes) using hardware", algorithm.name(), digest.length);
            return digest;

        } catch (DigestException e) {
            throw e;
        } catch (Exception e) {
            log.error("Error computing digest", e);
            throw new DigestException("Error computing digest", e);
        }
    }

    /**
     * Computes the digest using algorithm name string.
     *
     * @param algorithmName the algorithm name (e.g., "SHA-256", "MD5")
     * @param data          the data to hash
     * @return the computed digest
     * @throws IllegalArgumentException if algorithm name is unknown or data is null
     * @throws DigestException          if an error occurs during hashing
     */
    public byte[] digest(String algorithmName, byte[] data) {
        if (algorithmName == null) {
            throw new IllegalArgumentException("algorithmName cannot be null");
        }
        Algorithm algorithm = ALGORITHM_MAP.get(algorithmName.toUpperCase());
        if (algorithm == null) {
            throw new IllegalArgumentException("Unknown algorithm: " + algorithmName);
        }
        return digest(algorithm, data);
    }

    /**
     * Computes SHA-256 digest of the data.
     *
     * @param data the data to hash
     * @return the SHA-256 digest
     */
    public byte[] sha256(byte[] data) {
        return digest(Algorithm.SHA256, data);
    }

    /**
     * Computes SHA-384 digest of the data.
     *
     * @param data the data to hash
     * @return the SHA-384 digest
     */
    public byte[] sha384(byte[] data) {
        return digest(Algorithm.SHA384, data);
    }

    /**
     * Computes SHA-512 digest of the data.
     *
     * @param data the data to hash
     * @return the SHA-512 digest
     */
    public byte[] sha512(byte[] data) {
        return digest(Algorithm.SHA512, data);
    }

    /**
     * Computes SHA-1 digest of the data.
     *
     * @param data the data to hash
     * @return the SHA-1 digest
     */
    public byte[] sha1(byte[] data) {
        return digest(Algorithm.SHA1, data);
    }

    /**
     * Computes MD5 digest of the data.
     *
     * @param data the data to hash
     * @return the MD5 digest
     */
    public byte[] md5(byte[] data) {
        return digest(Algorithm.MD5, data);
    }

    /**
     * Computes RIPEMD-160 digest of the data.
     *
     * @param data the data to hash
     * @return the RIPEMD-160 digest
     */
    public byte[] ripemd160(byte[] data) {
        return digest(Algorithm.RIPEMD160, data);
    }

    /**
     * Converts a digest to hexadecimal string representation.
     *
     * @param digest the digest bytes
     * @return hexadecimal string
     */
    public static String toHex(byte[] digest) {
        if (digest == null) {
            throw new IllegalArgumentException("digest cannot be null");
        }
        StringBuilder sb = new StringBuilder(digest.length * 2);
        for (byte b : digest) {
            sb.append(String.format("%02x", b & 0xFF));
        }
        return sb.toString();
    }
}
