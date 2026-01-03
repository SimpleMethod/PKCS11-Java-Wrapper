package pl.mlodawski.security.pkcs11;

import lombok.extern.slf4j.Slf4j;
import pl.mlodawski.security.pkcs11.exceptions.*;
import pl.mlodawski.security.pkcs11.model.CertificateInfo;
import pl.mlodawski.security.pkcs11.model.KeyCertificatePair;
import pl.mlodawski.security.pkcs11.model.SupportedAlgorithm;
import pl.mlodawski.security.pkcs11.jna.Cryptoki;
import pl.mlodawski.security.pkcs11.jna.constants.AttributeType;
import pl.mlodawski.security.pkcs11.jna.constants.MechanismFlags;
import pl.mlodawski.security.pkcs11.jna.constants.MechanismType;
import pl.mlodawski.security.pkcs11.jna.constants.ObjectClass;
import pl.mlodawski.security.pkcs11.jna.constants.ReturnValue;
import pl.mlodawski.security.pkcs11.jna.structure.MechanismInfo;
import com.sun.jna.Native;
import com.sun.jna.NativeLong;
import com.sun.jna.ptr.NativeLongByReference;
import com.sun.jna.Memory;

import java.io.ByteArrayInputStream;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;


@Slf4j
public class PKCS11Utils {

    /**
     * Finds the matching pairs of private keys and certificates within a PKCS11 session.
     *
     * @param pkcs11   the PKCS11 object
     * @param session  the session object
     * @return a list of KeyCertificatePair objects representing the matching pairs
     * @throws IllegalArgumentException if pkcs11 or session is null
     * @throws RuntimeException if there is an error finding the private keys and certificates
     */
    public List<KeyCertificatePair> findPrivateKeysAndCertificates(Cryptoki pkcs11, NativeLong session) {
        if (pkcs11 == null) {
            throw new IllegalArgumentException("pkcs11 cannot be null");
        }
        if (session == null) {
            throw new IllegalArgumentException("session cannot be null");
        }

        List<KeyCertificatePair> pairs = new ArrayList<>();

        try {
            Map<String, NativeLong> certificateMap = findAllCertificates(pkcs11, session);
            Map<String, NativeLong> privateKeyMap = findAllPrivateKeys(pkcs11, session);

            for (Map.Entry<String, NativeLong> entry : certificateMap.entrySet()) {
                String ckaId = entry.getKey();
                NativeLong certHandle = entry.getValue();
                if (privateKeyMap.containsKey(ckaId)) {
                    NativeLong keyHandle = privateKeyMap.get(ckaId);
                    X509Certificate cert = getCertificate(pkcs11, session, certHandle);
                    CertificateInfo certInfo = createCertificateInfo(cert);
                    pairs.add(new KeyCertificatePair(keyHandle, cert, ckaId, certInfo));
                }
            }

            if (pairs.isEmpty()) {
                log.warn("No matching private key and certificate pairs found");
            }
        } catch (Exception e) {
            log.error("Error finding private keys and certificates", e);
            throw new KeyCertificatePairRetrievalException("Error finding private keys and certificates", e);
        }

        return pairs;
    }

    /**
     * Creates a CertificateInfo object based on the provided X509Certificate.
     *
     * @param cert the X509Certificate object from which to create the CertificateInfo
     * @return a CertificateInfo object representing the provided X509Certificate
     */
    private CertificateInfo createCertificateInfo(X509Certificate cert) {
        try {
            return new CertificateInfo(
                    cert.getSubjectX500Principal().getName(),
                    cert.getIssuerX500Principal().getName(),
                    cert.getSerialNumber(),
                    cert.getSignature(),
                    cert.getNotBefore(),
                    cert.getNotAfter(),
                    cert.getSigAlgName(),
                    cert.getSigAlgOID(),
                    cert.getTBSCertificate(),
                    cert.getVersion(),
                    cert.getPublicKey(),
                    cert.getIssuerUniqueID(),
                    cert.getSubjectUniqueID(),
                    cert.getKeyUsage(),
                    cert.getExtendedKeyUsage(),
                    cert.getBasicConstraints(),
                    cert.getSubjectAlternativeNames(),
                    cert.getIssuerAlternativeNames(),
                    cert.getEncoded()
            );
        } catch (Exception e) {
            log.error("Error creating CertificateInfo", e);
            throw new CertificateInfoCreationException("Error creating CertificateInfo", e);
        }
    }

    /**
     * Lists the supported algorithms for a given PKCS11 session and slot ID.
     *
     * @param pkcs11   the PKCS11 instance to use
     * @param session  the session identifier
     * @param slotID   the slot ID
     * @return a list of SupportedAlgorithm objects representing the supported algorithms
     * @throws IllegalArgumentException if pkcs11 or session is null
     * @throws RuntimeException         if there is an error listing the supported algorithms
     */
    public List<SupportedAlgorithm> listSupportedAlgorithms(Cryptoki pkcs11, NativeLong session, int slotID) {
        if (pkcs11 == null) {
            throw new IllegalArgumentException("pkcs11 cannot be null");
        }
        if (session == null) {
            throw new IllegalArgumentException("session cannot be null");
        }

        List<SupportedAlgorithm> algorithms = new ArrayList<>();

        try {
            NativeLong[] mechanismList = getMechanismList(pkcs11, new NativeLong(slotID));

            for (NativeLong mechanism : mechanismList) {
                MechanismInfo mechanismInfo = new MechanismInfo();
                NativeLong rv = pkcs11.C_GetMechanismInfo(new NativeLong(slotID), mechanism, mechanismInfo);

                if (ReturnValue.isSuccess(rv)) {
                    String mechanismName = getMechanismName(mechanism.longValue());
                    SupportedAlgorithm.AlgorithmType type = getAlgorithmType(mechanismInfo);
                    String mechanismCode = String.valueOf(mechanism.longValue());

                    algorithms.add(new SupportedAlgorithm(mechanismName, mechanismCode, type));
                }
            }
        } catch (Exception e) {
            log.error("Error listing supported algorithms", e);
            throw new AlgorithmListingException("Error listing supported algorithms", e);
        }

        return algorithms;
    }

    /**
     * Find all certificates in the PKCS#11 store.
     *
     * @param pkcs11   the PKCS11 object representing the store
     * @param session  the session ID for the PKCS#11 store
     * @return a map of certificate IDs to certificate handles
     * @throws IllegalArgumentException if pkcs11 or session is null
     * @throws RuntimeException if an error occurs while finding certificates
     */
    Map<String, NativeLong> findAllCertificates(Cryptoki pkcs11, NativeLong session) {
        if (pkcs11 == null) {
            throw new IllegalArgumentException("pkcs11 cannot be null");
        }
        if (session == null) {
            throw new IllegalArgumentException("session cannot be null");
        }

        Map<String, NativeLong> certificateMap = new HashMap<>();

        try {
            int attrSize = NativeLong.SIZE + Native.POINTER_SIZE + NativeLong.SIZE;
            Memory template = new Memory(attrSize);
            template.clear();

            Memory valueMemory = new Memory(NativeLong.SIZE);
            valueMemory.setNativeLong(0, new NativeLong(ObjectClass.CERTIFICATE));

            template.setNativeLong(0, new NativeLong(AttributeType.CLASS));
            template.setPointer(NativeLong.SIZE, valueMemory);
            template.setNativeLong(NativeLong.SIZE + Native.POINTER_SIZE, new NativeLong(NativeLong.SIZE));

            pkcs11.C_FindObjectsInit(session, template, new NativeLong(1));
            NativeLongByReference count = new NativeLongByReference();
            NativeLong[] certHandle = new NativeLong[1];

            while (true) {
                pkcs11.C_FindObjects(session, certHandle, new NativeLong(1), count);
                if (count.getValue().intValue() == 0) {
                    break;
                }
                String ckaId = getCKA_ID(pkcs11, session, certHandle[0]);
                certificateMap.put(ckaId, certHandle[0]);
            }
            pkcs11.C_FindObjectsFinal(session);
        } catch (Exception e) {
            log.error("Error finding certificates", e);
            throw new CertificateRetrievalException("Error finding certificates", e);
        }

        return certificateMap;
    }

    /**
     * Finds all private keys within a PKCS11 session.
     *
     * @param pkcs11   the PKCS11 instance
     * @param session  the native long value representing the session
     * @return a map of private keys, where the key is the CKA_ID and the value is the key handle
     * @throws IllegalArgumentException if pkcs11 or session is null
     * @throws RuntimeException if there is an error finding private keys
     */
    Map<String, NativeLong> findAllPrivateKeys(Cryptoki pkcs11, NativeLong session) {
        if (pkcs11 == null) {
            throw new IllegalArgumentException("pkcs11 cannot be null");
        }
        if (session == null) {
            throw new IllegalArgumentException("session cannot be null");
        }

        Map<String, NativeLong> privateKeyMap = new HashMap<>();

        try {
            int attrSize = NativeLong.SIZE + Native.POINTER_SIZE + NativeLong.SIZE;
            Memory template = new Memory(attrSize);
            template.clear();

            Memory valueMemory = new Memory(NativeLong.SIZE);
            valueMemory.setNativeLong(0, new NativeLong(ObjectClass.PRIVATE_KEY));

            template.setNativeLong(0, new NativeLong(AttributeType.CLASS));
            template.setPointer(NativeLong.SIZE, valueMemory);
            template.setNativeLong(NativeLong.SIZE + Native.POINTER_SIZE, new NativeLong(NativeLong.SIZE));

            pkcs11.C_FindObjectsInit(session, template, new NativeLong(1));
            NativeLongByReference count = new NativeLongByReference();
            NativeLong[] keyHandle = new NativeLong[1];

            while (true) {
                pkcs11.C_FindObjects(session, keyHandle, new NativeLong(1), count);
                if (count.getValue().intValue() == 0) {
                    break;
                }
                String ckaId = getCKA_ID(pkcs11, session, keyHandle[0]);
                privateKeyMap.put(ckaId, keyHandle[0]);
            }
            pkcs11.C_FindObjectsFinal(session);
        } catch (Exception e) {
            log.error("Error finding private keys", e);
            throw new PrivateKeyRetrievalException("Error finding private keys", e);
        }

        return privateKeyMap;
    }

    /**
     * Retrieves the CKA_ID attribute of an object from a PKCS#11 session.
     *
     * @param pkcs11          the PKCS11 object representing the PKCS#11 implementation
     * @param session         the session handle
     * @param objectHandle    the handle of the object
     * @return the CKA_ID attribute of the object as a hex string
     * @throws IllegalArgumentException if pkcs11, session, or objectHandle is null
     * @throws RuntimeException         if an error occurs while getting the CKA_ID attribute
     */
    String getCKA_ID(Cryptoki pkcs11, NativeLong session, NativeLong objectHandle) {
        if (pkcs11 == null) {
            throw new IllegalArgumentException("pkcs11 cannot be null");
        }
        if (session == null) {
            throw new IllegalArgumentException("session cannot be null");
        }
        if (objectHandle == null) {
            throw new IllegalArgumentException("objectHandle cannot be null");
        }

        try {
            int attrSize = NativeLong.SIZE + Native.POINTER_SIZE + NativeLong.SIZE;
            int pValueOffset = NativeLong.SIZE;
            int ulValueLenOffset = NativeLong.SIZE + Native.POINTER_SIZE;

            Memory template = new Memory(attrSize);
            template.clear();
            template.setNativeLong(0, new NativeLong(AttributeType.ID));

            pkcs11.C_GetAttributeValue(session, objectHandle, template, new NativeLong(1));

            int len = template.getNativeLong(ulValueLenOffset).intValue();
            if (len <= 0) {
                return "";
            }

            Memory ckaIdMemory = new Memory(len);
            template.setPointer(pValueOffset, ckaIdMemory);
            template.setNativeLong(ulValueLenOffset, new NativeLong(len));

            pkcs11.C_GetAttributeValue(session, objectHandle, template, new NativeLong(1));
            byte[] ckaId = ckaIdMemory.getByteArray(0, len);

            return bytesToHex(ckaId);
        } catch (Exception e) {
            log.error("Error getting CKA_ID", e);
            throw new AttributeRetrievalException("Error getting CKA_ID", e);
        }
    }

    /**
     * Retrieves and returns an X509Certificate using the provided PKCS11 instance, session, and certificate handle.
     *
     * @param pkcs11        the PKCS11 instance used for retrieving the certificate
     * @param session       the session used for retrieving the certificate
     * @param certHandle    the handle of the certificate to retrieve
     * @return the X509Certificate associated with the given certificate handle
     * @throws IllegalArgumentException if pkcs11, session, or certHandle is null
     * @throws RuntimeException if there is an error retrieving or creating the X509Certificate
     */
    X509Certificate getCertificate(Cryptoki pkcs11, NativeLong session, NativeLong certHandle) {
        if (pkcs11 == null) {
            throw new IllegalArgumentException("pkcs11 cannot be null");
        }
        if (session == null) {
            throw new IllegalArgumentException("session cannot be null");
        }
        if (certHandle == null) {
            throw new IllegalArgumentException("certHandle cannot be null");
        }

        try {
            int attrSize = NativeLong.SIZE + Native.POINTER_SIZE + NativeLong.SIZE;
            int pValueOffset = NativeLong.SIZE;
            int ulValueLenOffset = NativeLong.SIZE + Native.POINTER_SIZE;

            Memory template = new Memory(attrSize);
            template.clear();
            template.setNativeLong(0, new NativeLong(AttributeType.VALUE));

            pkcs11.C_GetAttributeValue(session, certHandle, template, new NativeLong(1));

            int len = template.getNativeLong(ulValueLenOffset).intValue();
            if (len <= 0) {
                throw new CertificateCreationException("Certificate has invalid length", null);
            }

            Memory certMemory = new Memory(len);
            template.setPointer(pValueOffset, certMemory);
            template.setNativeLong(ulValueLenOffset, new NativeLong(len));

            pkcs11.C_GetAttributeValue(session, certHandle, template, new NativeLong(1));
            byte[] certBytes = certMemory.getByteArray(0, len);

            CertificateFactory cf = CertificateFactory.getInstance("X.509");
            return (X509Certificate) cf.generateCertificate(new ByteArrayInputStream(certBytes));
        } catch (CertificateException e) {
            log.error("Error creating X509Certificate", e);
            throw new CertificateCreationException("Error creating X509Certificate", e);
        } catch (Exception e) {
            log.error("Error retrieving certificate", e);
            throw new CertificateCreationException("Error retrieving certificate", e);
        }
    }

    /**
     * Convert a byte array to a hexadecimal string.
     *
     * @param bytes the byte array to be converted
     * @return the hexadecimal string representation of the byte array
     * @throws IllegalArgumentException if the input byte array is null
     * @throws RuntimeException if an error occurs during the conversion process
     */
    static String bytesToHex(byte[] bytes) {
        if (bytes == null) {
            throw new IllegalArgumentException("bytes cannot be null");
        }

        try {
            StringBuilder result = new StringBuilder();
            for (byte b : bytes) {
                result.append(String.format("%02x", b));
            }
            return result.toString();
        } catch (Exception e) {
            log.error("Error converting bytes to hex", e);
            throw new ByteConversionException("Error converting bytes to hex", e);
        }
    }


    /**
     * Retrieves the list of mechanisms supported by a given PKCS11 slot.
     *
     * @param pkcs11    the PKCS11 instance to use for the operation (must not be null)
     * @param slotID    the ID of the slot to retrieve the mechanism list for (must not be null)
     * @return an array of NativeLong objects representing the supported mechanisms
     * @throws IllegalArgumentException if pkcs11 or slotID is null
     * @throws RuntimeException if an error occurred while retrieving the mechanism list
     */
    NativeLong[] getMechanismList(Cryptoki pkcs11, NativeLong slotID) {
        if (pkcs11 == null) {
            throw new IllegalArgumentException("pkcs11 cannot be null");
        }
        if (slotID == null) {
            throw new IllegalArgumentException("slotID cannot be null");
        }

        try {
            NativeLongByReference count = new NativeLongByReference();
            NativeLong rv = pkcs11.C_GetMechanismList(slotID, null, count);
            if (!ReturnValue.isSuccess(rv)) {
                throw new MechanismListRetrievalException("Failed to get mechanism count, error: " + rv.longValue(),null);
            }

            if (count.getValue().longValue() == 0) {
                return new NativeLong[0];
            }

            NativeLong[] mechanismList = new NativeLong[count.getValue().intValue()];
            rv = pkcs11.C_GetMechanismList(slotID, mechanismList, count);
            if (!ReturnValue.isSuccess(rv)) {
                throw new MechanismListRetrievalException("Failed to get mechanism list, error: " + rv.longValue(),null);
            }

            return mechanismList;
        } catch (Exception e) {
            log.error("Error getting mechanism list", e);
            throw new MechanismListRetrievalException("Error getting mechanism list", e);
        }
    }

    /**
     * Retrieves the name of the mechanism associated with the given mechanism code.
     *
     * @param mechanismCode the mechanism code
     * @return the name of the mechanism associated with the given mechanism code,
     *         or "UNKNOWN_MECHANISM_" followed by the mechanism code if no corresponding mechanism is found
     * @throws RuntimeException if an error occurs while determining the mechanism name
     */
    String getMechanismName(long mechanismCode) {
        try {
            return MechanismType.getName(mechanismCode);
        } catch (Exception e) {
            log.error("Error determining mechanism name", e);
            throw new MechanismNameRetrievalException("Error determining mechanism name", e);
        }
    }

    /**
     * Gets the algorithm type based on the given mechanism info.
     *
     * @param mechanismInfo The MechanismInfo object containing the mechanism information.
     * @return The algorithm type corresponding to the given mechanism info.
     * @throws IllegalArgumentException If mechanismInfo is null.
     * @throws RuntimeException If there is an error determining the algorithm type.
     */
    SupportedAlgorithm.AlgorithmType getAlgorithmType(MechanismInfo mechanismInfo) {
        if (mechanismInfo == null) {
            throw new IllegalArgumentException("mechanismInfo cannot be null");
        }

        try {
            if (mechanismInfo.flags.longValue() == 0) {
                return SupportedAlgorithm.AlgorithmType.UNKNOWN;
            }

            long flags = mechanismInfo.flags.longValue();

            Map<Long, SupportedAlgorithm.AlgorithmType> flagToType = Map.of(
                    MechanismFlags.SIGN, SupportedAlgorithm.AlgorithmType.SIGNATURE,
                    MechanismFlags.VERIFY, SupportedAlgorithm.AlgorithmType.VERIFICATION,
                    MechanismFlags.ENCRYPT, SupportedAlgorithm.AlgorithmType.ENCRYPTION,
                    MechanismFlags.DECRYPT, SupportedAlgorithm.AlgorithmType.DECRYPTION,
                    MechanismFlags.DIGEST, SupportedAlgorithm.AlgorithmType.DIGEST,
                    MechanismFlags.DERIVE, SupportedAlgorithm.AlgorithmType.KEY_AGREEMENT,
                    MechanismFlags.GENERATE, SupportedAlgorithm.AlgorithmType.KEY_GENERATION,
                    MechanismFlags.GENERATE_KEY_PAIR, SupportedAlgorithm.AlgorithmType.KEY_PAIR_GENERATION,
                    MechanismFlags.WRAP, SupportedAlgorithm.AlgorithmType.WRAP,
                    MechanismFlags.UNWRAP, SupportedAlgorithm.AlgorithmType.UNWRAP
            );

            return flagToType.entrySet().stream()
                    .filter(entry -> (flags & entry.getKey()) != 0)
                    .findFirst()
                    .map(Map.Entry::getValue)
                    .orElse(SupportedAlgorithm.AlgorithmType.UNKNOWN);
        } catch (Exception e) {
            log.error("Error determining algorithm type", e);
            throw new AlgorithmTypeRetrievalException("Error determining algorithm type", e);
        }
    }
}
