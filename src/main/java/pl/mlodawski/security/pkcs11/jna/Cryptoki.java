package pl.mlodawski.security.pkcs11.jna;

import com.sun.jna.Library;
import com.sun.jna.Native;
import com.sun.jna.NativeLong;
import com.sun.jna.Pointer;
import com.sun.jna.ptr.NativeLongByReference;
import pl.mlodawski.security.pkcs11.jna.structure.*;

/**
 * JNA interface for PKCS#11 (Cryptoki) library.
 * Provides access to PKCS#11 cryptographic token operations.
 * Based on OASIS PKCS#11 specification v2.40.
 */
public interface Cryptoki extends Library {

    /**
     * Loads a PKCS#11 library from the specified path.
     *
     * @param libraryPath Path to the PKCS#11 shared library (.dll, .so, .dylib)
     * @return Cryptoki interface instance
     */
    static Cryptoki loadLibrary(String libraryPath) {
        return Native.load(libraryPath, Cryptoki.class);
    }

    // ==================== General-purpose functions ====================

    /**
     * Initializes the Cryptoki library.
     *
     * @param pInitArgs Initialization arguments, or null for defaults
     * @return CKR_OK on success, or an error code
     */
    NativeLong C_Initialize(InitializeArgs pInitArgs);

    /**
     * Finalizes (shuts down) the Cryptoki library.
     *
     * @param pReserved Reserved parameter, must be null
     * @return CKR_OK on success, or an error code
     */
    NativeLong C_Finalize(Pointer pReserved);

    // ==================== Slot and token management ====================

    /**
     * Obtains a list of slots in the system.
     *
     * @param tokenPresent If non-zero, only slots with tokens present are returned
     * @param pSlotList    Array to receive slot IDs, or null to get count only
     * @param pulCount     On input: size of pSlotList; on output: number of slots
     * @return CKR_OK on success, or an error code
     */
    NativeLong C_GetSlotList(byte tokenPresent, NativeLong[] pSlotList, NativeLongByReference pulCount);

    /**
     * Obtains information about a particular slot.
     *
     * @param slotID Slot identifier
     * @param pInfo  Structure to receive slot information
     * @return CKR_OK on success, or an error code
     */
    NativeLong C_GetSlotInfo(NativeLong slotID, SlotInfo pInfo);

    /**
     * Obtains information about a particular token.
     *
     * @param slotID Slot identifier
     * @param pInfo  Structure to receive token information
     * @return CKR_OK on success, or an error code
     */
    NativeLong C_GetTokenInfo(NativeLong slotID, TokenInfo pInfo);

    // ==================== Mechanism information ====================

    /**
     * Obtains a list of mechanisms supported by a token.
     *
     * @param slotID           Slot identifier
     * @param pMechanismList   Array to receive mechanism types, or null to get count only
     * @param pulCount         On input: size of pMechanismList; on output: number of mechanisms
     * @return CKR_OK on success, or an error code
     */
    NativeLong C_GetMechanismList(NativeLong slotID, NativeLong[] pMechanismList, NativeLongByReference pulCount);

    /**
     * Obtains information about a particular mechanism.
     *
     * @param slotID Slot identifier
     * @param type   Mechanism type
     * @param pInfo  Structure to receive mechanism information
     * @return CKR_OK on success, or an error code
     */
    NativeLong C_GetMechanismInfo(NativeLong slotID, NativeLong type, MechanismInfo pInfo);

    // ==================== Session management ====================

    /**
     * Opens a session between an application and a token.
     *
     * @param slotID       Slot identifier
     * @param flags        Session flags (CKF_SERIAL_SESSION must be set)
     * @param pApplication Application-defined pointer (can be null)
     * @param Notify       Notification callback (can be null)
     * @param phSession    Receives the session handle
     * @return CKR_OK on success, or an error code
     */
    NativeLong C_OpenSession(NativeLong slotID, NativeLong flags, Pointer pApplication,
                             Pointer Notify, NativeLongByReference phSession);

    /**
     * Closes a session.
     *
     * @param hSession Session handle
     * @return CKR_OK on success, or an error code
     */
    NativeLong C_CloseSession(NativeLong hSession);

    /**
     * Closes all sessions with a token.
     *
     * @param slotID Slot identifier
     * @return CKR_OK on success, or an error code
     */
    NativeLong C_CloseAllSessions(NativeLong slotID);

    /**
     * Logs a user into a token.
     *
     * @param hSession  Session handle
     * @param userType  User type (CKU_USER or CKU_SO)
     * @param pPin      PIN value
     * @param ulPinLen  PIN length
     * @return CKR_OK on success, or an error code
     */
    NativeLong C_Login(NativeLong hSession, NativeLong userType, byte[] pPin, NativeLong ulPinLen);

    /**
     * Logs a user out of a token.
     *
     * @param hSession Session handle
     * @return CKR_OK on success, or an error code
     */
    NativeLong C_Logout(NativeLong hSession);

    // ==================== Object management ====================

    /**
     * Initializes a search for token and session objects.
     *
     * @param hSession  Session handle
     * @param pTemplate Pointer to template for matching attributes
     * @param ulCount   Number of attributes in template
     * @return CKR_OK on success, or an error code
     */
    NativeLong C_FindObjectsInit(NativeLong hSession, Pointer pTemplate, NativeLong ulCount);

    /**
     * Continues a search for token and session objects.
     *
     * @param hSession          Session handle
     * @param phObject          Array to receive object handles
     * @param ulMaxObjectCount  Maximum objects to return
     * @param pulObjectCount    Receives number of objects found
     * @return CKR_OK on success, or an error code
     */
    NativeLong C_FindObjects(NativeLong hSession, NativeLong[] phObject,
                             NativeLong ulMaxObjectCount, NativeLongByReference pulObjectCount);

    /**
     * Finishes a search for token and session objects.
     *
     * @param hSession Session handle
     * @return CKR_OK on success, or an error code
     */
    NativeLong C_FindObjectsFinal(NativeLong hSession);

    /**
     * Obtains the value of one or more attributes of an object.
     *
     * @param hSession  Session handle
     * @param hObject   Object handle
     * @param pTemplate Pointer to template specifying which attributes to get
     * @param ulCount   Number of attributes in template
     * @return CKR_OK on success, or an error code
     */
    NativeLong C_GetAttributeValue(NativeLong hSession, NativeLong hObject,
                                   Pointer pTemplate, NativeLong ulCount);

    // ==================== Signing and verification ====================

    /**
     * Initializes a signing operation.
     *
     * @param hSession   Session handle
     * @param pMechanism Signing mechanism
     * @param hKey       Handle of the signing key
     * @return CKR_OK on success, or an error code
     */
    NativeLong C_SignInit(NativeLong hSession, Mechanism pMechanism, NativeLong hKey);

    /**
     * Initializes a signing operation with mechanism as raw pointer.
     * Use this for complex mechanisms like RSA-PSS.
     *
     * @param hSession   Session handle
     * @param pMechanism Pointer to mechanism structure in native memory
     * @param hKey       Handle of the signing key
     * @return CKR_OK on success, or an error code
     */
    NativeLong C_SignInit(NativeLong hSession, Pointer pMechanism, NativeLong hKey);

    /**
     * Signs data in a single operation.
     *
     * @param hSession        Session handle
     * @param pData           Data to sign
     * @param ulDataLen       Data length
     * @param pSignature      Buffer for signature, or null to get length
     * @param pulSignatureLen On input: buffer size; on output: signature length
     * @return CKR_OK on success, or an error code
     */
    NativeLong C_Sign(NativeLong hSession, byte[] pData, NativeLong ulDataLen,
                      byte[] pSignature, NativeLongByReference pulSignatureLen);

    /**
     * Continues a multi-part signing operation by processing another data part.
     *
     * @param hSession   Session handle
     * @param pPart      Data part to sign
     * @param ulPartLen  Data part length
     * @return CKR_OK on success, or an error code
     */
    NativeLong C_SignUpdate(NativeLong hSession, byte[] pPart, NativeLong ulPartLen);

    /**
     * Finishes a multi-part signing operation and returns the signature.
     *
     * @param hSession        Session handle
     * @param pSignature      Buffer for signature, or null to get length
     * @param pulSignatureLen On input: buffer size; on output: signature length
     * @return CKR_OK on success, or an error code
     */
    NativeLong C_SignFinal(NativeLong hSession, byte[] pSignature, NativeLongByReference pulSignatureLen);

    /**
     * Initializes a verification operation.
     *
     * @param hSession   Session handle
     * @param pMechanism Verification mechanism
     * @param hKey       Handle of the verification key
     * @return CKR_OK on success, or an error code
     */
    NativeLong C_VerifyInit(NativeLong hSession, Mechanism pMechanism, NativeLong hKey);

    /**
     * Verifies a signature in a single operation.
     *
     * @param hSession       Session handle
     * @param pData          Original data
     * @param ulDataLen      Data length
     * @param pSignature     Signature to verify
     * @param ulSignatureLen Signature length
     * @return CKR_OK if signature is valid, or an error code
     */
    NativeLong C_Verify(NativeLong hSession, byte[] pData, NativeLong ulDataLen,
                        byte[] pSignature, NativeLong ulSignatureLen);

    // ==================== Encryption and decryption ====================

    /**
     * Initializes an encryption operation.
     *
     * @param hSession   Session handle
     * @param pMechanism Encryption mechanism
     * @param hKey       Handle of the encryption key
     * @return CKR_OK on success, or an error code
     */
    NativeLong C_EncryptInit(NativeLong hSession, Mechanism pMechanism, NativeLong hKey);

    /**
     * Encrypts data in a single operation.
     *
     * @param hSession           Session handle
     * @param pData              Data to encrypt
     * @param ulDataLen          Data length
     * @param pEncryptedData     Buffer for encrypted data, or null to get length
     * @param pulEncryptedDataLen On input: buffer size; on output: encrypted data length
     * @return CKR_OK on success, or an error code
     */
    NativeLong C_Encrypt(NativeLong hSession, byte[] pData, NativeLong ulDataLen,
                         byte[] pEncryptedData, NativeLongByReference pulEncryptedDataLen);

    /**
     * Initializes a decryption operation.
     *
     * @param hSession   Session handle
     * @param pMechanism Decryption mechanism
     * @param hKey       Handle of the decryption key
     * @return CKR_OK on success, or an error code
     */
    NativeLong C_DecryptInit(NativeLong hSession, Mechanism pMechanism, NativeLong hKey);

    /**
     * Initializes a decryption operation with mechanism as raw pointer.
     * Use this for complex mechanisms like RSA-OAEP.
     *
     * @param hSession   Session handle
     * @param pMechanism Pointer to mechanism structure in native memory
     * @param hKey       Handle of the decryption key
     * @return CKR_OK on success, or an error code
     */
    NativeLong C_DecryptInit(NativeLong hSession, Pointer pMechanism, NativeLong hKey);

    /**
     * Decrypts data in a single operation.
     *
     * @param hSession           Session handle
     * @param pEncryptedData     Encrypted data
     * @param ulEncryptedDataLen Encrypted data length
     * @param pData              Buffer for decrypted data, or null to get length
     * @param pulDataLen         On input: buffer size; on output: decrypted data length
     * @return CKR_OK on success, or an error code
     */
    NativeLong C_Decrypt(NativeLong hSession, byte[] pEncryptedData, NativeLong ulEncryptedDataLen,
                         byte[] pData, NativeLongByReference pulDataLen);

    // ==================== Digest (Hash) operations ====================

    /**
     * Initializes a digest operation.
     *
     * @param hSession   Session handle
     * @param pMechanism Digest mechanism
     * @return CKR_OK on success, or an error code
     */
    NativeLong C_DigestInit(NativeLong hSession, Mechanism pMechanism);

    /**
     * Digests data in a single operation.
     *
     * @param hSession     Session handle
     * @param pData        Data to digest
     * @param ulDataLen    Data length
     * @param pDigest      Buffer for digest, or null to get length
     * @param pulDigestLen On input: buffer size; on output: digest length
     * @return CKR_OK on success, or an error code
     */
    NativeLong C_Digest(NativeLong hSession, byte[] pData, NativeLong ulDataLen,
                        byte[] pDigest, NativeLongByReference pulDigestLen);

    // ==================== Key management ====================

    /**
     * Generates a secret key.
     *
     * @param hSession   Session handle
     * @param pMechanism Key generation mechanism
     * @param pTemplate  Pointer to key attributes template
     * @param ulCount    Number of attributes
     * @param phKey      Receives the new key handle
     * @return CKR_OK on success, or an error code
     */
    NativeLong C_GenerateKey(NativeLong hSession, Mechanism pMechanism,
                             Pointer pTemplate, NativeLong ulCount, NativeLongByReference phKey);

    /**
     * Generates a public/private key pair.
     *
     * @param hSession              Session handle
     * @param pMechanism            Key generation mechanism
     * @param pPublicKeyTemplate    Pointer to public key attributes
     * @param ulPublicKeyAttrCount  Number of public key attributes
     * @param pPrivateKeyTemplate   Pointer to private key attributes
     * @param ulPrivateKeyAttrCount Number of private key attributes
     * @param phPublicKey           Receives the public key handle
     * @param phPrivateKey          Receives the private key handle
     * @return CKR_OK on success, or an error code
     */
    NativeLong C_GenerateKeyPair(NativeLong hSession, Mechanism pMechanism,
                                 Pointer pPublicKeyTemplate, NativeLong ulPublicKeyAttrCount,
                                 Pointer pPrivateKeyTemplate, NativeLong ulPrivateKeyAttrCount,
                                 NativeLongByReference phPublicKey, NativeLongByReference phPrivateKey);

    /**
     * Wraps (encrypts) a key.
     *
     * @param hSession       Session handle
     * @param pMechanism     Wrapping mechanism
     * @param hWrappingKey   Handle of wrapping key
     * @param hKey           Handle of key to wrap
     * @param pWrappedKey    Buffer for wrapped key, or null to get length
     * @param pulWrappedKeyLen On input: buffer size; on output: wrapped key length
     * @return CKR_OK on success, or an error code
     */
    NativeLong C_WrapKey(NativeLong hSession, Mechanism pMechanism, NativeLong hWrappingKey,
                         NativeLong hKey, byte[] pWrappedKey, NativeLongByReference pulWrappedKeyLen);

    /**
     * Unwraps (decrypts) a key.
     *
     * @param hSession         Session handle
     * @param pMechanism       Unwrapping mechanism
     * @param hUnwrappingKey   Handle of unwrapping key
     * @param pWrappedKey      Wrapped key data
     * @param ulWrappedKeyLen  Wrapped key length
     * @param pTemplate        Pointer to unwrapped key attributes
     * @param ulAttrCount      Number of attributes
     * @param phKey            Receives the unwrapped key handle
     * @return CKR_OK on success, or an error code
     */
    NativeLong C_UnwrapKey(NativeLong hSession, Mechanism pMechanism, NativeLong hUnwrappingKey,
                           byte[] pWrappedKey, NativeLong ulWrappedKeyLen,
                           Pointer pTemplate, NativeLong ulAttrCount, NativeLongByReference phKey);

    /**
     * Derives a key from a base key.
     *
     * @param hSession      Session handle
     * @param pMechanism    Key derivation mechanism (e.g., ECDH1_DERIVE)
     * @param hBaseKey      Handle of the base key (e.g., EC private key)
     * @param pTemplate     Pointer to template for derived key attributes
     * @param ulAttrCount   Number of attributes in template
     * @param phKey         Receives the derived key handle
     * @return CKR_OK on success, or an error code
     */
    NativeLong C_DeriveKey(NativeLong hSession, Mechanism pMechanism, NativeLong hBaseKey,
                           Pointer pTemplate, NativeLong ulAttrCount, NativeLongByReference phKey);

    // ==================== Random number generation ====================

    /**
     * Generates random data.
     *
     * @param hSession   Session handle
     * @param pRandomData Buffer for random data
     * @param ulRandomLen Number of random bytes to generate
     * @return CKR_OK on success, or an error code
     */
    NativeLong C_GenerateRandom(NativeLong hSession, byte[] pRandomData, NativeLong ulRandomLen);
}
