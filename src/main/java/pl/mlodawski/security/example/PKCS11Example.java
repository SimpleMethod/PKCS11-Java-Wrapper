package pl.mlodawski.security.example;

import pl.mlodawski.security.pkcs11.*;
import pl.mlodawski.security.pkcs11.model.*;

import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.*;

class PKCS11 {
    private final Path PKCS11_WRAPPER_PATH;
    private String PIN;
    private final PKCS11Utils utils = new PKCS11Utils();
    private PKCS11Device selectedDevice;

    public PKCS11(Path pkcs11WrapperPath) {
        this.PKCS11_WRAPPER_PATH = pkcs11WrapperPath;
    }

    public void run() {
        try (PKCS11Manager manager = new PKCS11Manager(PKCS11_WRAPPER_PATH)) {
            manager.registerDeviceChangeListener(new DeviceChangeListener() {
                @Override
                public void onDeviceConnected(PKCS11Device device) {
                    System.out.println("\nNew device connected: " + device.getLabel());
                }

                @Override
                public void onDeviceDisconnected(PKCS11Device device) {
                    System.out.println("\nDevice disconnected: " + device.getLabel());
                    if (device.equals(selectedDevice)) {
                        selectedDevice = null;
                        System.out.println("Selected device was disconnected. Please select a new device.");
                    }
                }

                @Override
                public void onDeviceStateChanged(PKCS11Device device, DeviceState oldState) {
                    System.out.printf("\nDevice %s state changed from %s to %s%n",
                            device.getLabel(), oldState, device.getState());
                }

                @Override
                public void onDeviceError(PKCS11Device device, Exception error) {
                    System.out.printf("\nError occurred with device %s: %s%n",
                            device.getLabel(), error.getMessage());
                }
            });

            while (true) {
                try {
                    if (selectedDevice == null || !selectedDevice.isReady()) {
                        if (!selectDevice(manager)) {
                            System.out.println("No devices available. Please connect a device and try again.");
                            Thread.sleep(2000);
                            continue;
                        }
                        if (!getPINFromUser()) {
                            continue;
                        }
                    }

                    try (PKCS11Session session = manager.openSession(selectedDevice, PIN)) {
                        while (selectedDevice != null && selectedDevice.isReady()) {
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
                                    signFile(manager, session);
                                    break;
                                case 4:
                                    verifyFileSignature(manager, session);
                                    break;
                                case 5:
                                    encryptDecryptData(manager, session);
                                    break;
                                case 6:
                                    encryptDecryptFile(manager, session);
                                    break;
                                case 7:
                                    listSupportedAlgorithms(manager, session);
                                    break;
                                case 8:
                                    selectedDevice = null;
                                    return;
                                case 9:
                                    session.close();
                                    selectedDevice = null;
                                    PIN = null;
                                    if (!handleDeviceChange(manager)) {
                                        System.out.println("Returning to main menu...");
                                    }
                                    break;
                                default:
                                    System.out.println("Invalid choice. Please try again.");
                            }

//                            if (choice == 6) {
//                                break;
//                            }
                        }
                    } catch (Exception e) {
                        System.out.println("Session error: " + e.getMessage());
                        selectedDevice = null;
                        PIN = null;
                    }
                } catch (Exception e) {
                    System.out.println("An error occurred: " + e.getMessage());
                    Thread.sleep(1000);
                }
            }
        } catch (Exception e) {
            throw new RuntimeException("Fatal error: " + e.getMessage(), e);
        }
    }

    private void signFile(PKCS11Manager manager, PKCS11Session session) {
        try {
            KeyCertificatePair selectedPair = selectCertificateKeyPair(manager, session);

            System.out.print("Enter path to file to sign: ");
            Scanner scanner = new Scanner(System.in);
            String filePath = scanner.nextLine();

            Path path = Paths.get(filePath);
            if (!Files.exists(path)) {
                System.out.println("File does not exist: " + filePath);
                return;
            }

            byte[] fileContent = Files.readAllBytes(path);
            PKCS11Signer signer = new PKCS11Signer();
            byte[] signature = signer.signMessage(manager.getPkcs11(),
                    session.getSession(),
                    selectedPair.getKeyHandle(),
                    fileContent);

            // Save signature to file
            String signatureFilePath = filePath + ".sig";
            Files.write(Paths.get(signatureFilePath), signature);

            System.out.println("File signed successfully. Signature saved to: " + signatureFilePath);
            System.out.println("Signature (Base64): " + Base64.getEncoder().encodeToString(signature));

            // Verify signature immediately
            boolean isSignatureValid = signer.verifySignature(fileContent, signature, selectedPair.getCertificate());
            System.out.println("Signature verification: " + (isSignatureValid ? "Valid" : "Invalid"));
        } catch (Exception e) {
            System.out.println("Error during file signing: " + e.getMessage());
            throw new RuntimeException(e);
        }
    }

    private void verifyFileSignature(PKCS11Manager manager, PKCS11Session session) {
        try {
            KeyCertificatePair selectedPair = selectCertificateKeyPair(manager, session);
            Scanner scanner = new Scanner(System.in);

            System.out.print("Enter path to file to verify: ");
            String filePath = scanner.nextLine();

            System.out.print("Enter path to signature file: ");
            String signatureFilePath = scanner.nextLine();

            if (!Files.exists(Paths.get(filePath))) {
                System.out.println("File does not exist: " + filePath);
                return;
            }
            if (!Files.exists(Paths.get(signatureFilePath))) {
                System.out.println("Signature file does not exist: " + signatureFilePath);
                return;
            }

            byte[] fileContent = Files.readAllBytes(Paths.get(filePath));
            byte[] signature = Files.readAllBytes(Paths.get(signatureFilePath));

            PKCS11Signer signer = new PKCS11Signer();
            boolean isSignatureValid = signer.verifySignature(fileContent, signature, selectedPair.getCertificate());

            System.out.println("Signature verification result: " + (isSignatureValid ? "Valid" : "Invalid"));
        } catch (Exception e) {
            System.out.println("Error during signature verification: " + e.getMessage());
        }
    }

    private void encryptDecryptFile(PKCS11Manager manager, PKCS11Session session) {
        try {
            KeyCertificatePair selectedPair = selectCertificateKeyPair(manager, session);
            Scanner scanner = new Scanner(System.in);

            System.out.print("Enter path to file to encrypt: ");
            String filePath = scanner.nextLine();

            if (!Files.exists(Paths.get(filePath))) {
                System.out.println("File does not exist: " + filePath);
                return;
            }

            byte[] fileContent = Files.readAllBytes(Paths.get(filePath));

            // Encrypt file using hybrid encryption
            PKCS11Crypto crypto = new PKCS11Crypto();
            byte[][] encryptedPackage = crypto.encryptData(fileContent, selectedPair.getCertificate());

            // Save encrypted components
            String encryptedKeyPath = filePath + ".key.enc";
            String encryptedIVPath = filePath + ".iv";
            String encryptedDataPath = filePath + ".data.enc";

            Files.write(Paths.get(encryptedKeyPath), encryptedPackage[0]);
            Files.write(Paths.get(encryptedIVPath), encryptedPackage[1]);
            Files.write(Paths.get(encryptedDataPath), encryptedPackage[2]);

            System.out.println("File encrypted successfully.");
            System.out.println("Encrypted key saved to: " + encryptedKeyPath);
            System.out.println("IV saved to: " + encryptedIVPath);
            System.out.println("Encrypted data saved to: " + encryptedDataPath);

            System.out.println("\nDo you want to decrypt the file? (y/n)");
            String answer = scanner.nextLine().toLowerCase();
            if (!answer.equals("y")) {
                return;
            }

            // Decrypt file
            byte[][] decryptPackage = new byte[][]{
                    Files.readAllBytes(Paths.get(encryptedKeyPath)),
                    Files.readAllBytes(Paths.get(encryptedIVPath)),
                    Files.readAllBytes(Paths.get(encryptedDataPath))
            };

            byte[] decryptedData = crypto.decryptData(
                    manager.getPkcs11(),
                    session.getSession(),
                    selectedPair.getKeyHandle(),
                    decryptPackage
            );

            // Save decrypted file
            String decryptedFilePath = filePath + ".dec";
            Files.write(Paths.get(decryptedFilePath), decryptedData);
            System.out.println("File decrypted successfully. Saved to: " + decryptedFilePath);

            // Calculate and display checksums
            String originalChecksum = getFileChecksum(fileContent);
            String decryptedChecksum = getFileChecksum(decryptedData);

            System.out.println("\nFile integrity verification:");
            System.out.println("Original file SHA-256: " + originalChecksum);
            System.out.println("Decrypted file SHA-256: " + decryptedChecksum);

            if (Arrays.equals(fileContent, decryptedData)) {
                System.out.println("File integrity verified: Original and decrypted files match.");
            } else {
                System.out.println("Warning: Decrypted file does not match original!");
            }
        } catch (Exception e) {
            System.out.println("Error during file encryption/decryption: " + e.getMessage());
        }
    }

    private String getFileChecksum(byte[] fileData) throws NoSuchAlgorithmException {
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        byte[] hash = digest.digest(fileData);
        return Base64.getEncoder().encodeToString(hash);
    }

    private boolean handleDeviceChange(PKCS11Manager manager) {
        int maxRetries = 3;
        int retryCount = 0;

        while (retryCount < maxRetries) {
            try {
                manager.prepareForDeviceChange();
                System.out.println("Device selection refreshed. Please select a new device.");

                if (!selectDevice(manager)) {
                    retryCount++;
                    continue;
                }

                if (!getPINFromUser()) {
                    retryCount++;
                    continue;
                }

                return true;
            } catch (Exception e) {
                System.err.println("Error during device change"+ e);
                retryCount++;
                if (retryCount < maxRetries) {
                    System.out.println("Error occurred, retrying... (" + (maxRetries - retryCount) + " attempts remaining)");
                    try {
                        Thread.sleep(1000);
                    } catch (InterruptedException ie) {
                        Thread.currentThread().interrupt();
                        return false;
                    }
                }
            }
        }

        System.out.println("Failed to change device after " + maxRetries + " attempts.");
        return false;
    }

    private boolean selectDevice(PKCS11Manager manager) {
        List<PKCS11Device> devices = manager.listDevices();
        if (devices.isEmpty()) {
            return false;
        }

        System.out.println("\n--- Available Devices ---");
        for (int i = 0; i < devices.size(); i++) {
            PKCS11Device device = devices.get(i);
            System.out.printf("%d: %s (Manufacturer: %s, Model: %s, Serial: %s)%n",
                    i + 1,
                    device.getLabel(),
                    device.getManufacturer(),
                    device.getModel(),
                    device.getSerialNumber());

            Map<String, String> info = device.getDetailedInfo();
            System.out.printf("   State: %s%n", device.getState());
            System.out.printf("   Rest of the information about key: %s", info.toString());
            System.out.println();
        }

        System.out.print("Select device (1-" + devices.size() + "): ");
        int choice = getUserChoice();

        if (choice < 1 || choice > devices.size()) {
            System.out.println("Invalid device selection.");
            return false;
        }

        selectedDevice = devices.get(choice - 1);
        if (!selectedDevice.isReady()) {
            System.out.println("Selected device is not ready. State: " + selectedDevice.getState());
            selectedDevice = null;
            return false;
        }

        return true;
    }

    private boolean getPINFromUser() {
        if (selectedDevice == null) {
            return false;
        }

        Map<String, Long> pinRequirements = selectedDevice.getPinLengthRequirements();
        System.out.print("Enter PIN for " + selectedDevice.getLabel() + ": ");
        Scanner scanner = new Scanner(System.in);
        PIN = scanner.nextLine();

        if (PIN.length() < pinRequirements.get("minLength") ||
                PIN.length() > pinRequirements.get("maxLength")) {
            System.out.printf("Invalid PIN length. Must be between %d and %d characters.%n",
                    pinRequirements.get("minLength"),
                    pinRequirements.get("maxLength"));
            PIN = null;
            return false;
        }

        return true;
    }

    private void displayMenu() {
        System.out.println("\n--- PKCS#11 Operations Menu ---");
        System.out.println("Current device: " + selectedDevice.getLabel());
        System.out.println("1. List Available Certificates");
        System.out.println("2. Sign a Message");
        System.out.println("3. Sign a File");
        System.out.println("4. Verify File Signature");
        System.out.println("5. Encrypt and Decrypt Data");
        System.out.println("6. Encrypt and Decrypt File");
        System.out.println("7. List Supported Algorithms");
        System.out.println("8. Exit");
        System.out.println("9. Change Device");
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

            PKCS11Crypto crypto = new PKCS11Crypto();

            // Encrypt data
            byte[][] encryptedPackage = crypto.encryptData(dataToEncrypt.getBytes(), selectedPair.getCertificate());
            System.out.println("Data encrypted successfully.");
            System.out.println("Encrypted data (Base64): " + Base64.getEncoder().encodeToString(encryptedPackage[2]));

            // Decrypt data
            byte[] decryptedData = crypto.decryptData(
                    manager.getPkcs11(),
                    session.getSession(),
                    selectedPair.getKeyHandle(),
                    encryptedPackage
            );
            System.out.println("Decrypted data: " + new String(decryptedData));

            if (dataToEncrypt.equals(new String(decryptedData))) {
                System.out.println("Encryption and decryption successful: data integrity verified.");
            } else {
                System.out.println("Warning: Decrypted data does not match original input.");
            }
        } catch (IllegalArgumentException e) {
            System.out.println("Invalid input: " + e.getMessage());
        } catch (Exception e) {
            System.out.println("Error during encryption/decryption: " + e.getMessage());
        }
    }

    private void listSupportedAlgorithms(PKCS11Manager manager, PKCS11Session session) {
        try {
            List<SupportedAlgorithm> algorithms = utils.listSupportedAlgorithms(
                    manager.getPkcs11(),
                    session.getSession(),
                    selectedDevice.getSlotId().intValue()
            );

            if (algorithms.isEmpty()) {
                System.out.println("\nNo supported algorithms found for this device.");
                return;
            }

            System.out.println("\nSupported algorithms:");
            for (SupportedAlgorithm algo : algorithms) {
                System.out.println(algo);
            }
        } catch (Exception e) {
            System.out.println("Error listing algorithms: " + e.getMessage());
        }
    }
}


public class PKCS11Example {
    public static void main(String[] args) {
        String userDir = System.getProperty("user.dir");
        PKCS11 example = new PKCS11(
                Paths.get(userDir, "lib", "opensc-pkcs11.dll")
        );
        example.run();
    }
}