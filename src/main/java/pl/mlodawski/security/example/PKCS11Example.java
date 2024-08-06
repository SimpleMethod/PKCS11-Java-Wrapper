package pl.mlodawski.security.example;

import pl.mlodawski.security.pkcs11.*;
import pl.mlodawski.security.pkcs11.model.SupportedAlgorithm;
import pl.mlodawski.security.pkcs11.model.KeyCertificatePair;
import pl.mlodawski.security.pkcs11.model.CertificateInfo;

import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.List;
import java.util.Base64;
import java.util.Scanner;

class PKCS11 {

    private final Path PKCS11_WRAPPER_PATH;
    private final String PIN;
    PKCS11Utils utils = new PKCS11Utils();

    public PKCS11(Path pkcs11WrapperPath, String pin) {
        this.PKCS11_WRAPPER_PATH = pkcs11WrapperPath;
        this.PIN = pin;
    }

    public void run() {
        PKCS11Manager manager = new PKCS11Manager(PKCS11_WRAPPER_PATH, PIN);

        try (PKCS11Session session = manager.openSession(0)) {
            while (true) {
                try {
                    displayMenu();
                    int choice = getUserChoice();

                    switch (choice) {
                        case 1:
                            listCertificates(manager, session);
                            break;
                        case 2:
                            signMessage(manager, session);
                            break;
                        case 3:
                            encryptDecryptData(manager, session);
                            break;
                        case 4:
                            listSupportedAlgorithms(manager, session);
                            break;
                        case 5:
                            System.out.println("Exiting...");
                            return;
                        default:
                            System.out.println("Invalid choice. Please try again.");
                    }
                } catch (Exception e) {
                    System.out.println("An error occurred: " + e.getMessage());
                } finally {
                    session.resetSession();
                }
            }
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    private void displayMenu() {
        System.out.println("\n--- PKCS#11 Operations Menu ---");
        System.out.println("1. List Available Certificates");
        System.out.println("2. Sign a Message");
        System.out.println("3. Encrypt and Decrypt Data");
        System.out.println("4. List Supported Algorithms");
        System.out.println("5. Exit");
        System.out.print("Enter your choice: ");
    }

    private int getUserChoice() {
        Scanner scanner = new Scanner(System.in);
        return scanner.nextInt();
    }

    private void listCertificates(PKCS11Manager manager, PKCS11Session session) {
        List<KeyCertificatePair> pairs = utils.findPrivateKeysAndCertificates(manager.getPkcs11(), session.getSession());
        System.out.println("\nAvailable certificate-key pairs:");
        for (int i = 0; i < pairs.size(); i++) {
            KeyCertificatePair pair = pairs.get(i);
            CertificateInfo certInfo = pair.getCertificateInfo();
            System.out.printf("%d: Subject: %s, Issuer: %s, Serial: %s, Not Before: %s, Not After: %s, CKA_ID: %s\n",
                    i + 1,
                    certInfo.getSubject(),
                    certInfo.getIssuer(),
                    certInfo.getSerialNumber(),
                    certInfo.getNotBefore(),
                    certInfo.getNotAfter(),
                    pair.getCkaId());
        }
    }

    private KeyCertificatePair selectCertificateKeyPair(PKCS11Manager manager, PKCS11Session session) {
        List<KeyCertificatePair> pairs = utils.findPrivateKeysAndCertificates(manager.getPkcs11(), session.getSession());
        listCertificates(manager, session);
        System.out.print("Select a certificate-key pair index: ");
        int pairIndex = getUserChoice() - 1;

        if (pairIndex < 0 || pairIndex >= pairs.size()) {
            throw new IllegalArgumentException("Invalid certificate-key pair index selected.");
        }

        return pairs.get(pairIndex);
    }

    private void signMessage(PKCS11Manager manager, PKCS11Session session) throws Exception {
        try {
            KeyCertificatePair selectedPair = selectCertificateKeyPair(manager, session);

            System.out.print("Enter a message to sign: ");
            Scanner scanner = new Scanner(System.in);
            String messageToSign = scanner.nextLine();

            PKCS11Signer signer = new PKCS11Signer();
            byte[] signature = signer.signMessage(manager.getPkcs11(), session.getSession(), selectedPair.getKeyHandle(), messageToSign.getBytes());
            System.out.println("Signature: " + Base64.getEncoder().encodeToString(signature));

            boolean isSignatureValid = signer.verifySignature(messageToSign.getBytes(), signature, selectedPair.getCertificate());
            System.out.println("Signature status: " + (isSignatureValid ? "Valid" : "Invalid"));
        } catch (Exception e) {
            System.out.println("Error during signing: " + e.getMessage());
            throw e;
        }
    }

    private void encryptDecryptData(PKCS11Manager manager, PKCS11Session session) {
        try {
            KeyCertificatePair selectedPair = selectCertificateKeyPair(manager, session);

            System.out.print("Enter data to encrypt: ");
            Scanner scanner = new Scanner(System.in);
            String dataToEncrypt = scanner.nextLine();

            PKCS11Crypto decryptor = new PKCS11Crypto();

            byte[] encryptedData = decryptor.encryptData(dataToEncrypt.getBytes(), selectedPair.getCertificate());
            System.out.println("Data encrypted successfully.");

            byte[] decryptedData = decryptor.decryptData(manager.getPkcs11(), session.getSession(), selectedPair.getKeyHandle(), encryptedData);
            System.out.println("Decrypted data: " + new String(decryptedData));

            if (dataToEncrypt.equals(new String(decryptedData))) {
                System.out.println("Encryption and decryption successful: data integrity verified.");
            } else {
                System.out.println("Warning: Decrypted data does not match original input.");
            }
        } catch (IllegalArgumentException e) {
            System.out.println("Invalid input: " + e.getMessage());
            throw e;
        } catch (Exception e) {
            System.out.println("Error during encryption/decryption: " + e.getMessage());
            throw e;
        }
    }

    private void listSupportedAlgorithms(PKCS11Manager manager, PKCS11Session session) {
        List<SupportedAlgorithm> algorithms = utils.listSupportedAlgorithms(manager.getPkcs11(), session.getSession(), 0);
        System.out.println("\nSupported algorithms:");
        for (SupportedAlgorithm algo : algorithms) {
            System.out.println(algo);
        }
    }
}

public class PKCS11Example {
    public static void main(String[] args) {
        String userDir = System.getProperty("user.dir");
        PKCS11 example = new PKCS11(
                Paths.get(userDir, "lib", "opensc-pkcs11.dll"),
                "123456"
        );
        example.run();
    }
}