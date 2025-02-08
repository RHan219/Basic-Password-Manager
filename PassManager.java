import java.io.*;
import javax.crypto.*;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.util.Base64;
import java.util.Scanner;

public class PassManager {
    private Cipher cipher;
    private SecretKeySpec key;
    private String keyString;

    public static void main(String[] args) throws Exception {
        PassManager passmanager = new PassManager();
        passmanager.managerPrompt();
    }

    public void managerPrompt() throws Exception {
        SecureRandom random = new SecureRandom();
        byte[] salt = Base64.getDecoder().decode("ZY1kxrD843mGRVORU58JLA==");
        Scanner scanner = new Scanner(System.in);

        System.out.print("Enter the keyString to access your passwords: ");
        keyString = scanner.nextLine();

        KeySpec spec = new PBEKeySpec(keyString.toCharArray(), salt, 1024, 128);
        SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
        SecretKey privateKey = factory.generateSecret(spec);
        
        setCipher(Cipher.getInstance("AES"));
        key = new SecretKeySpec(privateKey.getEncoded(), "AES");

        File file = new File(keyString);
        if (!file.exists()) {
            System.out.println("No password file detected. Creating a new password file.");
            file.createNewFile();
            try (FileWriter writer = new FileWriter(keyString, true)) {
                writer.write("salt: " + salt + "\n");
            }
        }

        while (true) {
            System.out.println("a : Add Password\n" +
                    "r : Read Password\n" +
                    "q : Quit\n" +
                    "Enter choice: ");
            
            String action = scanner.nextLine();
            
            switch (action) {
                case "a":
                    System.out.println("Enter label for password: ");
                    String passLabel = scanner.nextLine();
                    
                    System.out.println("Enter password to store: ");
                    String password = scanner.nextLine();
                    
                    addPass(passLabel, password);
                    break;
                
                case "r":
                    System.out.println("Enter label for password: ");
                    passLabel = scanner.nextLine();
                    
                    String retrievedPassword = readPass(passLabel);
                    System.out.println("Found: " + (retrievedPassword != null ? retrievedPassword : "No Password Found"));
                    break;
                
                case "q":
                    scanner.close();
                    return;
                
                default:
                    System.out.println("Invalid option. Try again.");
            }
        }
    }

    private void setCipher(Cipher cipher) {
        this.cipher = cipher;
    }

    private void addPass(String label, String password) throws Exception {
        String encryptedPassword = encryptPass(password);
        try (FileWriter writer = new FileWriter(keyString, true)) {
            writer.write(label + ":" + encryptedPassword + "\n");
        }
    }

    private String encryptPass(String password) throws Exception {
        cipher.init(Cipher.ENCRYPT_MODE, key);
        byte[] encryptedData = cipher.doFinal(password.getBytes());
        return Base64.getEncoder().encodeToString(encryptedData);
    }

    private String readPass(String label) throws Exception {
        File file = new File(keyString);
        Scanner scanner = new Scanner(file);
        
        while (scanner.hasNextLine()) {
            String line = scanner.nextLine();
            if (line.startsWith(label + ":")) {
                scanner.close();
                return decryptPass(line.split(":")[1]);
            }
        }
        scanner.close();
        return null;
    }

    private String decryptPass(String encryptedPassword) throws Exception {
        cipher.init(Cipher.DECRYPT_MODE, key);
        byte[] encryptedData = Base64.getDecoder().decode(encryptedPassword);
        byte[] decryptedData = cipher.doFinal(encryptedData);
        return new String(decryptedData);
    }
}
