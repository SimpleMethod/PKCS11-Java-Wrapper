package pl.mlodawski.security.pkcs11.model;

import lombok.Value;

/**
 * Represents a supported cryptographic algorithm.
 */
@Value
public class SupportedAlgorithm {
    /**
     * The name field represents the name of the algorithm.
     */
    String name;

    /**
     * The code field represents the code of the algorithm.
     */
    String code;
    /**
     * The AlgorithmType enumeration represents different types of algorithms.
     * <p>
     * An algorithm type can be used to identify and differentiate between various algorithms in a program.
     * It provides a standardized way to handle different algorithm types in code.
     * <p>
     * The AlgorithmType enum consists of the following constants:
     * - SIGNATURE: Represents the signature of a method or a class.
     * - ENCRYPTION: Represents the encryption algorithm used for secure communication.
     * - KEY_AGREEMENT: Represents a key agreement algorithm used in cryptography.
     * - VERIFICATION: Used for verification purposes.
     * - DECRYPTION: Represents the decryption process for a given algorithm.
     * - DIGEST: Represents the digest value of a message or data.
     * - KEY_GENERATION: Represents the key generation process.
     * - KEY_PAIR_GENERATION: Represents the process of generating a cryptographic key pair.
     * - WRAP: Represents the action of wrapping a cryptographic key.
     * - UNWRAP: Represents the action of unwrapping a cryptographic key.
     * - UNKNOWN: Represents an unknown algorithm type.
     * <p>
     * Example usage:
     * AlgorithmType type = AlgorithmType.ENCRYPTION;
     */
    AlgorithmType type;

    public enum AlgorithmType {
        /**
         * This variable represents the signature of a method or a class.
         * <p>
         * A signature is the unique combination of the name and parameter types of a method, or the name
         * of a class. It is used to identify and differentiate between various methods or classes in a
         * program.
         * <p>
         * The signature can be used for various purposes, such as method overloading, method overriding,
         * and reflection. It is particularly useful when the programmer wants to identify a specific
         * method or class based on its name and parameter types.
         */
        SIGNATURE,
        /**
         * ENCRYPTION is a static final variable that represents the encryption algorithm used for secure communication.
         * It is recommended to use this variable to ensure consistent encryption across the application.
         * <p>
         * This variable is of type String and is initialized with the encryption algorithm "AES".
         * It should not be modified, as changing the value can potentially compromise the security of the application.
         * <p>
         * Example usage:
         * String algorithm = ENCRYPTION;
         */
        ENCRYPTION,
        /**
         * Represents a key agreement algorithm used in cryptography.
         */
        KEY_AGREEMENT,
        /**
         * This variable is used for verification purposes.
         */
        VERIFICATION,
        /**
         * Represents the decryption process for a given algorithm.
         * This variable is used to configure and execute the decryption process.
         * <p>
         * Usage Example:
         * <p>
         * // Instantiate the DECRYPTION object
         * Decryption decryption = new Decryption();
         * <p>
         * // Set the cipher algorithm
         * decryption.setAlgorithm("AES");
         * <p>
         * // Set the key for decryption
         * decryption.setKey("mySecretKey");
         * <p>
         * // Set the initialization vector
         * decryption.setIV("myIV");
         * <p>
         * // Set the input data for decryption
         * decryption.setInputData("encryptedData");
         * <p>
         * // Execute the decryption process
         * decryption.execute();
         */
        DECRYPTION,
        /**
         * The DIGEST variable represents the digest value of a message or data.
         * It is typically used to validate the integrity and authenticity of the data.
         * The digest value is computed using a cryptographic algorithm such as SHA-256.
         * <p>
         * The type of DIGEST is implementation-specific, and it can be a byte array, a hex string,
         * or any other suitable representation depending on the requirements of the project.
         * <p>
         * Example usage:
         * <p>
         * byte[] message = "Hello, World!".getBytes();
         * DigestAlgorithm digestAlgorithm = DigestAlgorithm.SHA256;
         * byte[] digest = computeDigest(message, digestAlgorithm);
         * <p>
         * // Validate the integrity of the message by comparing the digest value
         * boolean isIntegrityValid = validateDigest(message, digest, digestAlgorithm);
         */
        DIGEST,
        /**
         * Represents the key generation process.
         */
        KEY_GENERATION,
        /**
         * The KEY_PAIR_GENERATION variable is used to specify the process of generating a cryptographic key pair.
         */
        KEY_PAIR_GENERATION,
        /**
         * The WRAP algorithm type represents the action of wrapping a cryptographic key.
         * <p>
         * In the context of cryptography, the term "wrapping" refers to the process of encrypting a key to protect its confidentiality
         * and integrity. Wrapping is commonly used in key management systems to securely export a key for storage or transfer it to a
         * different component.
         * <p>
         * The WRAP algorithm type is defined as a constant in the AlgorithmType enum. It is used to identify the algorithm type
         * associated with the wrapping operation in a key management or cryptographic system. Other algorithm types defined in
         * the enum include SIGNATURE, ENCRYPTION, KEY_AGREEMENT, VERIFICATION, DECRYPTION, DIGEST, KEY_GENERATION, KEY_PAIR_GENERATION,
         * and UNWRAP.
         * <p>
         * This enum constant should be used when a wrapping operation is being performed or when an algorithm type is expected
         * to be associated with the wrapping of a cryptographic key. It provides a clear and standardized way to identify and handle
         * wrapping operations in code.
         * <p>
         * Note that the WRAP algorithm type is specific to a particular implementation or cryptographic provider. Different providers
         * may use different names or identifiers for the same algorithm. It is recommended to consult the documentation and guidelines
         * of the specific provider to get more details about the properties and usage of the WRAP algorithm type in that context.
         */
        WRAP,
        /**
         * The UNWRAP algorithm type represents the action of unwrapping a cryptographic key.
         * <p>
         * In the context of cryptography, the term "unwrapping" refers to the process of importing an encrypted key from a secure
         * container or token and decrypting it to obtain the original plain key. This operation is commonly used in key management
         * systems to transfer encrypted keys securely between different components or to extract a key for use in a cryptographic
         * operation.
         * <p>
         * The UNWRAP algorithm type is defined as a constant in the AlgorithmType enum. It is used to identify the algorithm type
         * associated with the unwrapping operation in a key management or cryptographic system. Other algorithm types defined in
         * the enum include SIGNATURE, ENCRYPTION, KEY_AGREEMENT, VERIFICATION, DECRYPTION, DIGEST, KEY_GENERATION, KEY_PAIR_GENERATION,
         * WRAP, and UNKNOWN.
         * <p>
         * This enum constant should be used when an unwrapping operation is being performed or when an algorithm type is expected
         * to be associated with the unwrapping of a cryptographic key. It provides a clear and standardized way to identify and handle
         * unwrapping operations in code.
         * <p>
         * Note that the UNWRAP algorithm type is specific to a particular implementation or cryptographic provider. Different providers
         * may use different names or identifiers for the same algorithm. It is recommended to consult the documentation and guidelines
         * of the specific provider to get more details about the properties and usage of the UNWRAP algorithm type in that context.
         */
        UNWRAP,
        /**
         * Represents an unknown algorithm type.
         * <p>
         * This enum constant is used to represent an algorithm type that is not explicitly defined in the AlgorithmType enum.
         * It can be used when encountering an unknown or unsupported algorithm type, or when a specific algorithm type is expected
         * but not provided.
         * <p>
         * Note that relying on UNKNOWN algorithm type might introduce potential issues, as it should be used as a fallback option
         * or for handling unexpected scenarios only.
         */
        UNKNOWN
    }
}
