package pl.mlodawski.security.pkcs11;

import com.sun.jna.Memory;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import pl.mlodawski.security.pkcs11.exceptions.*;
import pl.mlodawski.security.pkcs11.model.KeyCertificatePair;
import pl.mlodawski.security.pkcs11.model.SupportedAlgorithm;
import ru.rutoken.pkcs11jna.*;

import com.sun.jna.NativeLong;
import com.sun.jna.ptr.NativeLongByReference;

import java.security.cert.X509Certificate;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class PKCS11UtilsTest {

    @Mock
    private Pkcs11 pkcs11Mock;
    @Mock
    private X509Certificate certificateMock;

    private PKCS11Utils pkcs11Utils;
    private NativeLong session;
    private NativeLong certHandle;
    private NativeLong privateKeyHandle;

    @BeforeEach
    void setUp() {
        pkcs11Utils = new PKCS11Utils();
        session = new NativeLong(1L);
        certHandle = new NativeLong(2L);
        privateKeyHandle = new NativeLong(3L);
    }

    @Test
    void findPrivateKeysAndCertificates_nullPkcs11_shouldThrowIllegalArgumentException() {
        assertThrows(IllegalArgumentException.class, () -> pkcs11Utils.findPrivateKeysAndCertificates(null, session));
    }

    @Test
    void findPrivateKeysAndCertificates_nullSession_shouldThrowIllegalArgumentException() {
        assertThrows(IllegalArgumentException.class, () -> pkcs11Utils.findPrivateKeysAndCertificates(pkcs11Mock, null));
    }

    @Test
    void listSupportedAlgorithms_nullPkcs11_shouldThrowIllegalArgumentException() {
        assertThrows(IllegalArgumentException.class, () -> pkcs11Utils.listSupportedAlgorithms(null, session, 1));
    }

    @Test
    void listSupportedAlgorithms_nullSession_shouldThrowIllegalArgumentException() {
        assertThrows(IllegalArgumentException.class, () -> pkcs11Utils.listSupportedAlgorithms(pkcs11Mock, null, 1));
    }


    @Test
    void findAllCertificates_nullPkcs11_shouldThrowIllegalArgumentException() {
        assertThrows(IllegalArgumentException.class, () -> pkcs11Utils.findAllCertificates(null, session));
    }

    @Test
    void findAllCertificates_nullSession_shouldThrowIllegalArgumentException() {
        assertThrows(IllegalArgumentException.class, () -> pkcs11Utils.findAllCertificates(pkcs11Mock, null));
    }

    @Test
    void findAllPrivateKeys_nullPkcs11_shouldThrowIllegalArgumentException() {
        assertThrows(IllegalArgumentException.class, () -> pkcs11Utils.findAllPrivateKeys(null, session));
    }

    @Test
    void findAllPrivateKeys_nullSession_shouldThrowIllegalArgumentException() {
        assertThrows(IllegalArgumentException.class, () -> pkcs11Utils.findAllPrivateKeys(pkcs11Mock, null));
    }

    @Test
    void getCKA_ID_validInput_shouldReturnCKA_ID() {
        // Mock behavior for C_GetAttributeValue
        when(pkcs11Mock.C_GetAttributeValue(any(NativeLong.class), any(NativeLong.class), any(CK_ATTRIBUTE[].class), any(NativeLong.class)))
                .thenAnswer(invocation -> {
                    CK_ATTRIBUTE[] template = invocation.getArgument(2);
                    template[0].pValue = new Memory(1);
                    template[0].ulValueLen = new NativeLong(1);
                    return new NativeLong(Pkcs11Constants.CKR_OK);
                });

        String ckaId = pkcs11Utils.getCKA_ID(pkcs11Mock, session, certHandle);
        assertNotNull(ckaId);
        assertFalse(ckaId.isEmpty());
    }

    @Test
    void getCKA_ID_nullPkcs11_shouldThrowIllegalArgumentException() {
        assertThrows(IllegalArgumentException.class, () -> pkcs11Utils.getCKA_ID(null, session, certHandle));
    }

    @Test
    void getCKA_ID_nullSession_shouldThrowIllegalArgumentException() {
        assertThrows(IllegalArgumentException.class, () -> pkcs11Utils.getCKA_ID(pkcs11Mock, null, certHandle));
    }

    @Test
    void getCertificate_nullPkcs11_shouldThrowIllegalArgumentException() {
        assertThrows(IllegalArgumentException.class, () -> pkcs11Utils.getCertificate(null, session, certHandle));
    }

    @Test
    void getCertificate_nullSession_shouldThrowIllegalArgumentException() {
        assertThrows(IllegalArgumentException.class, () -> pkcs11Utils.getCertificate(pkcs11Mock, null, certHandle));
    }

    @Test
    void getCertificate_nullCertHandle_shouldThrowIllegalArgumentException() {
        assertThrows(IllegalArgumentException.class, () -> pkcs11Utils.getCertificate(pkcs11Mock, session, null));
    }

    @Test
    void bytesToHex_validInput_shouldReturnHexString() {
        byte[] bytes = {0x1, 0x2F, 0x3A};
        String hexString = pkcs11Utils.bytesToHex(bytes);
        assertEquals("012f3a", hexString);
    }

    @Test
    void bytesToHex_nullInput_shouldThrowIllegalArgumentException() {
        assertThrows(IllegalArgumentException.class, () -> pkcs11Utils.bytesToHex(null));
    }

    @Test
    void getMechanismList_validInput_shouldReturnMechanismList() {
        // Mock behavior for C_GetMechanismList
        when(pkcs11Mock.C_GetMechanismList(any(NativeLong.class), any(), any(NativeLongByReference.class)))
                .thenAnswer(invocation -> {
                    NativeLongByReference count = invocation.getArgument(2);
                    count.setValue(new NativeLong(1));
                    return new NativeLong(Pkcs11Constants.CKR_OK);
                });
        when(pkcs11Mock.C_GetMechanismList(any(NativeLong.class), any(NativeLong[].class), any(NativeLongByReference.class)))
                .thenReturn(new NativeLong(Pkcs11Constants.CKR_OK));

        NativeLong[] mechanismList = pkcs11Utils.getMechanismList(pkcs11Mock, session);
        assertNotNull(mechanismList);
        assertEquals(1, mechanismList.length);
    }

    @Test
    void getMechanismList_nullPkcs11_shouldThrowIllegalArgumentException() {
        assertThrows(IllegalArgumentException.class, () -> pkcs11Utils.getMechanismList(null, session));
    }

    @Test
    void getMechanismList_nullSlotID_shouldThrowIllegalArgumentException() {
        assertThrows(IllegalArgumentException.class, () -> pkcs11Utils.getMechanismList(pkcs11Mock, null));
    }

    @Test
    void getMechanismName_validInput_shouldReturnMechanismName() {
        long mechanismCode = Pkcs11Constants.CKM_RSA_PKCS;
        String mechanismName = pkcs11Utils.getMechanismName(mechanismCode);
        assertNotNull(mechanismName);
        assertFalse(mechanismName.isEmpty());
    }

    @Test
    void getMechanismName_unknownMechanism_shouldReturnUnknownMechanism() {
        long unknownMechanismCode = 9999L;
        String mechanismName = pkcs11Utils.getMechanismName(unknownMechanismCode);
        assertEquals("UNKNOWN_MECHANISM_9999", mechanismName);
    }

    @Test
    void getAlgorithmType_validInput_shouldReturnAlgorithmType() {
        CK_MECHANISM_INFO mechanismInfo = new CK_MECHANISM_INFO();
        mechanismInfo.flags = new NativeLong(Pkcs11Constants.CKF_SIGN);
        SupportedAlgorithm.AlgorithmType algorithmType = pkcs11Utils.getAlgorithmType(mechanismInfo);
        assertEquals(SupportedAlgorithm.AlgorithmType.SIGNATURE, algorithmType);
    }

    @Test
    void getAlgorithmType_nullMechanismInfo_shouldThrowIllegalArgumentException() {
        assertThrows(IllegalArgumentException.class, () -> pkcs11Utils.getAlgorithmType(null));
    }
}
