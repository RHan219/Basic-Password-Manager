import java.io.*;
import javax.crypto.*;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.*;
import java.security.spec.KeySpec;
import java.util.Base64;
import java.util.Scanner;

public class PassMan {
    private Cipher cipher;
    private SecretKeySpec key;
    private String keyString;
    private byte[] salt = new byte[16];

    public static void main(String[] args) throws Exception {
        PassMan passmanager = new PassMan();
        passmanager.managerPrompt();
    }

    public void managerPrompt() throws Exception {
        SecureRandom random = new SecureRandom();
        random.nextBytes(salt);

        String saltString = "ZY1kxrD843mGRVORU58JLA==";
        salt = Base64.getDecoder().decode(saltString.getBytes());
        Scanner scanner = new Scanner(System.in);

        System.out.print("Enter the passcode to access your passwords: ");
        keyString = scanner.nextLine();

        KeySpec spec = new PBEKeySpec(keyString.toCharArray(), salt, 1024, 128);
        SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
        SecretKey privateKey = factory.generateSecret(spec);
        
        setCipher(Cipher.getInstance("AES"));
        key = new SecretKeySpec(privateKey.getEncoded(), "AES");

        Boolean valid = false;
        File file = new File("Passwords");

        // check if the Passwords file exists
        if (!file.exists()) {
            // create new Passwords file
            System.out.println("No password file detected. Creating a new password file.");
            file.createNewFile();

            try (FileWriter writer = new FileWriter("Passwords", true)) {
                // add salt and encrypted token to top of file
                String token = encryptPass(keyString);
                writer.write(saltString + ":" + token + "\n");

                valid = true;
            }
        }
        // if the file does exist, check if the passcode matches the encrypted token
        else {
            Scanner fileScanner = new Scanner(new File("Passwords"));
            if (fileScanner.hasNextLine()) {
                String[] parts = fileScanner.nextLine().split(":");
                
                String token = encryptPass(keyString);

                // if the passcode matches the token, it is considered valid.
                if (token.equals(parts[1])) {
                    valid = true;
                }
                // code stops if passcode is not valid
                else {
                    fileScanner.close();
                    System.out.println("Error: Incorrect passcode.");
                }
            }
        }

        while (valid) {
            System.out.print("a : Add Password\n" +
                    "r : Read Password\n" +
                    "q : Quit\n" +
                    "Enter choice: ");
            
            String action = scanner.nextLine();
            
            switch (action) {
                case "a":
                    System.out.print("Enter label for password: ");
                    String passLabel = scanner.nextLine();
                    
                    System.out.print("Enter password to store: ");
                    String password = scanner.nextLine();
                    
                    addPass(passLabel, password);
                    System.out.println();
                    break;
                
                case "r":
                    System.out.print("Enter label for password: ");
                    passLabel = scanner.nextLine();
                    
                    String retrievedPassword = readPass(passLabel);
                    System.out.println("Found: " + (retrievedPassword != null ? retrievedPassword : "No Password Found"));
                    System.out.println();
                    break;
                
                case "q":
                    scanner.close();
                    System.out.println("Quitting");
                    System.exit(0);
                
                default:
                    System.out.println("Invalid option. Try again.");
            }
        }
        scanner.close();
    }

    private void setCipher(Cipher cipher) {
        this.cipher = cipher;
    }

    // method to add a new password to our encrypted file
    private void addPass(String label, String password) throws Exception {
        // check to see if any passwords already use this label, and replace if needed
        checkPasswords(label);

        // encrypt password, and add it to file.
        String encryptedPassword = encryptPass(password);
        try (FileWriter writer = new FileWriter("Passwords", true)) {
            writer.write(label + ":" + encryptedPassword + "\n");
        }
    }

    // method to check password file
    // if a password already has the label, rewrite file to replace it.
    private void checkPasswords(String label) throws IOException {
        File file = new File("Passwords");
        Scanner scanner = new Scanner(file);
        
        // rewrite file without repeated label
        while (scanner.hasNextLine()) {
            String line = scanner.nextLine();
            if (line.startsWith(label + ":")) {
                rewriteFile(label);
            }
        }
        scanner.close();
    }

    // method to rewrite the file
    private void rewriteFile(String label) throws IOException {
        File file = new File("Passwords");
        File tempfile = new File("TempFile");
        Scanner scanner = new Scanner(file);
        FileWriter writer = new FileWriter(tempfile, true);
        
        // copy each line from the original file, to a new one
        // except for the repeated label
        while (scanner.hasNextLine()) {
            String line = scanner.nextLine();
            
            if (line.startsWith(label + ":")) {
                continue;
            }
            else {
                writer.write(line + "\n");
            }
        }
        scanner.close();
        writer.close();

        // make the new file the password file
        tempfile.renameTo(file);
    }

    // method to encrypt any given passwords
    private String encryptPass(String password) throws Exception {
        cipher.init(Cipher.ENCRYPT_MODE, key);
        byte[] encryptedData = cipher.doFinal(password.getBytes());

        // returns encrypted password
        return Base64.getEncoder().encodeToString(encryptedData);
    }

    // method to read any desired passwords
    private String readPass(String label) throws Exception {
        File file = new File("Passwords");
        Scanner scanner = new Scanner(file);
        
        while (scanner.hasNextLine()) {
            String line = scanner.nextLine();

            // check if this is the password we want
            if (line.startsWith(label + ":")) {
                scanner.close();

                // decrypt password
                return decryptPass(line.split(":")[1]);
            }
        }
        scanner.close();
        return null;
    }

    // method to decrypt any desried password
    private String decryptPass(String encryptedPassword) throws Exception {
        cipher.init(Cipher.DECRYPT_MODE, key);
        byte[] encryptedData = Base64.getDecoder().decode(encryptedPassword);
        byte[] decryptedData = cipher.doFinal(encryptedData);
        return new String(decryptedData);
    }
}
