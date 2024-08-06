package pl.mlodawski.security.pkcs11;

import lombok.extern.slf4j.Slf4j;
import pl.mlodawski.security.pkcs11.exceptions.*;
import pl.mlodawski.security.pkcs11.model.CertificateInfo;
import pl.mlodawski.security.pkcs11.model.KeyCertificatePair;
import pl.mlodawski.security.pkcs11.model.SupportedAlgorithm;
import ru.rutoken.pkcs11jna.*;
import com.sun.jna.NativeLong;
import com.sun.jna.ptr.NativeLongByReference;
import com.sun.jna.Memory;

import java.io.ByteArrayInputStream;
import java.lang.reflect.Field;
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
    public List<KeyCertificatePair> findPrivateKeysAndCertificates(Pkcs11 pkcs11, NativeLong session) {
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
    public List<SupportedAlgorithm> listSupportedAlgorithms(Pkcs11 pkcs11, NativeLong session, int slotID) {
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
                CK_MECHANISM_INFO mechanismInfo = new CK_MECHANISM_INFO();
                NativeLong rv = pkcs11.C_GetMechanismInfo(new NativeLong(slotID), mechanism, mechanismInfo);

                if (rv.longValue() == Pkcs11Constants.CKR_OK) {
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
    Map<String, NativeLong> findAllCertificates(Pkcs11 pkcs11, NativeLong session) {
        if (pkcs11 == null) {
            throw new IllegalArgumentException("pkcs11 cannot be null");
        }
        if (session == null) {
            throw new IllegalArgumentException("session cannot be null");
        }

        Map<String, NativeLong> certificateMap = new HashMap<>();

        try {
            CK_ATTRIBUTE[] template = (CK_ATTRIBUTE[]) new CK_ATTRIBUTE().toArray(1);

            Memory classMemory = new Memory(NativeLong.SIZE);
            classMemory.setNativeLong(0, new NativeLong(Pkcs11Constants.CKO_CERTIFICATE));
            template[0].type = new NativeLong(Pkcs11Constants.CKA_CLASS);
            template[0].pValue = classMemory;
            template[0].ulValueLen = new NativeLong(NativeLong.SIZE);

            pkcs11.C_FindObjectsInit(session, template, new NativeLong(template.length));
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
    Map<String, NativeLong> findAllPrivateKeys(Pkcs11 pkcs11, NativeLong session) {
        if (pkcs11 == null) {
            throw new IllegalArgumentException("pkcs11 cannot be null");
        }
        if (session == null) {
            throw new IllegalArgumentException("session cannot be null");
        }

        Map<String, NativeLong> privateKeyMap = new HashMap<>();

        try {
            CK_ATTRIBUTE[] template = (CK_ATTRIBUTE[]) new CK_ATTRIBUTE().toArray(1);

            Memory classMemory = new Memory(NativeLong.SIZE);
            classMemory.setNativeLong(0, new NativeLong(Pkcs11Constants.CKO_PRIVATE_KEY));
            template[0].type = new NativeLong(Pkcs11Constants.CKA_CLASS);
            template[0].pValue = classMemory;
            template[0].ulValueLen = new NativeLong(NativeLong.SIZE);

            pkcs11.C_FindObjectsInit(session, template, new NativeLong(template.length));
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
    String getCKA_ID(Pkcs11 pkcs11, NativeLong session, NativeLong objectHandle) {
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
            CK_ATTRIBUTE[] template = (CK_ATTRIBUTE[]) new CK_ATTRIBUTE().toArray(1);
            template[0].type = new NativeLong(Pkcs11Constants.CKA_ID);
            template[0].pValue = null;
            template[0].ulValueLen = new NativeLong(0);

            pkcs11.C_GetAttributeValue(session, objectHandle, template, new NativeLong(1));

            byte[] ckaId = new byte[(int) template[0].ulValueLen.longValue()];
            Memory ckaIdMemory = new Memory(ckaId.length);
            template[0].pValue = ckaIdMemory;
            pkcs11.C_GetAttributeValue(session, objectHandle, template, new NativeLong(1));
            ckaIdMemory.read(0, ckaId, 0, ckaId.length);

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
    X509Certificate getCertificate(Pkcs11 pkcs11, NativeLong session, NativeLong certHandle) {
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
            CK_ATTRIBUTE[] template = (CK_ATTRIBUTE[]) new CK_ATTRIBUTE().toArray(1);
            template[0].type = new NativeLong(Pkcs11Constants.CKA_VALUE);
            template[0].pValue = null;
            template[0].ulValueLen = new NativeLong(0);

            pkcs11.C_GetAttributeValue(session, certHandle, template, new NativeLong(1));

            byte[] certBytes = new byte[(int) template[0].ulValueLen.longValue()];
            Memory certMemory = new Memory(certBytes.length);
            template[0].pValue = certMemory;
            pkcs11.C_GetAttributeValue(session, certHandle, template, new NativeLong(1));
            certMemory.read(0, certBytes, 0, certBytes.length);

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
    NativeLong[] getMechanismList(Pkcs11 pkcs11, NativeLong slotID) {
        if (pkcs11 == null) {
            throw new IllegalArgumentException("pkcs11 cannot be null");
        }
        if (slotID == null) {
            throw new IllegalArgumentException("slotID cannot be null");
        }

        try {
            NativeLongByReference count = new NativeLongByReference();
            pkcs11.C_GetMechanismList(slotID, null, count);

            NativeLong[] mechanismList = new NativeLong[count.getValue().intValue()];
            pkcs11.C_GetMechanismList(slotID, mechanismList, count);

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
            for (Field field : Pkcs11Constants.class.getDeclaredFields()) {
                if (field.getName().startsWith("CKM_")) {
                    try {
                        if (field.getLong(null) == mechanismCode) {
                            return field.getName();
                        }
                    } catch (IllegalAccessException e) {
                        log.error("Error accessing field: {}", field.getName(), e);
                    }
                }
            }
            return "UNKNOWN_MECHANISM_" + mechanismCode;
        } catch (Exception e) {
            log.error("Error determining mechanism name", e);
            throw new MechanismNameRetrievalException("Error determining mechanism name", e);
        }
    }

    /**
     * Gets the algorithm type based on the given mechanism info.
     *
     * @param mechanismInfo The CK_MECHANISM_INFO object containing the mechanism information.
     * @return The algorithm type corresponding to the given mechanism info.
     * @throws IllegalArgumentException If mechanismInfo is null.
     * @throws RuntimeException If there is an error determining the algorithm type.
     */
    SupportedAlgorithm.AlgorithmType getAlgorithmType(CK_MECHANISM_INFO mechanismInfo) {
        if (mechanismInfo == null) {
            throw new IllegalArgumentException("mechanismInfo cannot be null");
        }

        try {
            if (mechanismInfo.flags.longValue() == 0) {
                return SupportedAlgorithm.AlgorithmType.UNKNOWN;
            }

            long flags = mechanismInfo.flags.longValue();

            Map<Long, SupportedAlgorithm.AlgorithmType> flagToType = Map.of(
                    Pkcs11Constants.CKF_SIGN, SupportedAlgorithm.AlgorithmType.SIGNATURE,
                    Pkcs11Constants.CKF_VERIFY, SupportedAlgorithm.AlgorithmType.VERIFICATION,
                    Pkcs11Constants.CKF_ENCRYPT, SupportedAlgorithm.AlgorithmType.ENCRYPTION,
                    Pkcs11Constants.CKF_DECRYPT, SupportedAlgorithm.AlgorithmType.DECRYPTION,
                    Pkcs11Constants.CKF_DIGEST, SupportedAlgorithm.AlgorithmType.DIGEST,
                    Pkcs11Constants.CKF_DERIVE, SupportedAlgorithm.AlgorithmType.KEY_AGREEMENT,
                    Pkcs11Constants.CKF_GENERATE, SupportedAlgorithm.AlgorithmType.KEY_GENERATION,
                    Pkcs11Constants.CKF_GENERATE_KEY_PAIR, SupportedAlgorithm.AlgorithmType.KEY_PAIR_GENERATION,
                    Pkcs11Constants.CKF_WRAP, SupportedAlgorithm.AlgorithmType.WRAP,
                    Pkcs11Constants.CKF_UNWRAP, SupportedAlgorithm.AlgorithmType.UNWRAP
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
