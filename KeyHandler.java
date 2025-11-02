/* CS6349 Network Security: Secure Relay-Based Chat System
 * By Parisa Nawar (pxn210032) and Aendri Singh (axs210369)
 * 
 * Handles publishing and reading public key data 
 */

import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.nio.file.Files;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PublicKey;
import java.security.spec.X509EncodedKeySpec;
import java.util.*;

public class KeyHandler {
    private final String PUBLIC_KEY_DIR = "PublicKeys";
    private final String RELAY_NAME = "Relay";
    private String hostname;
    private File keyFile;
    private KeyPair kp;

    // Creates a file to store the user's public key
    // Result = false indicates file already exists
    public boolean setUser(String hostname) throws Exception {
        keyFile = new File(PUBLIC_KEY_DIR + "/" + hostname + ".txt");
        this.hostname = hostname;

        // Check if file already exists
        if (keyFile.exists() && keyFile.isFile()){
            return false;
        }
        else {
            // Open file
            keyFile.createNewFile();
            return true;
        }
    }

    // Deletes user file 
    public boolean deleteUser() {
        if (hostname != null && keyFile != null) {
            keyFile.delete();
            return true;
        }
        return false;
    }

    // Creates a public private key pair and publishes it
    public void createKeyPair() throws Exception {
        if (hostname == null) {
            System.out.println("Error: No username! ");
            throw new UnknownUser();
        }

        // Generate key pair
        try {
            KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
            kpg.initialize(1024); 
            kp = kpg.generateKeyPair();
        } catch (Exception e) {
            System.out.println("Error: Unable to create key pair! " + e);
            throw e;
        }

        // Write to file
        /**try {
            Files.write(keyFile.toPath(), kp.getPublic().getEncoded());
        } catch (Exception e) {
            System.out.println("Error: Unable to publish public key! " + e);
            throw e;
        } */

        
    }

    // Returns the key pair
    public KeyPair getKeyPair() {
        return kp;
    }
    
    // Returns a list of all available users (besides user and relay)
    public List<String> getAvailableUsers() {
        File directory = new File(PUBLIC_KEY_DIR);
        File[] files = directory.listFiles();
        List<String> users = new ArrayList<>();

        // Add names to list
        if (files != null) {
            for (File file : files) {
                String name = file.getName().substring(0, file.getName().length()-4);
                if (!name.equals(RELAY_NAME) && !name.equals(hostname)) {
                    users.add(name);
                }
            }
        }
        return users;
    }

    // Returns the public key of the given user
    // (null if user not found)
    public PublicKey getUserPublicKey(String user) {
        /**File userFile = new File(PUBLIC_KEY_DIR + "/" + user + ".txt");
        if (userFile.exists() && userFile.isFile()) {
            try {
                byte[] byteKey = Files.readAllBytes(userFile.toPath());
                X509EncodedKeySpec X509publicKey = new X509EncodedKeySpec(byteKey);
                KeyFactory kf = KeyFactory.getInstance("RSA");

                return kf.generatePublic(X509publicKey);
            } catch (Exception e) {
                System.out.println("Error: Unable to read from public key file! " + e);
            } 
        }
        return null;*/

        File userFile = new File(PUBLIC_KEY_DIR + "/" + user + ".txt");
        if (userFile.exists() && userFile.isFile()) {
            try(FileInputStream fs = new FileInputStream(userFile); BufferedReader reader = new BufferedReader(new InputStreamReader(fs))){
                String uidLine = reader.readLine();
                if(uidLine == null) return null;

                byte[] byteKey = fs.readAllBytes();
                X509EncodedKeySpec X509publicKey = new X509EncodedKeySpec(byteKey);
                KeyFactory kf = KeyFactory.getInstance("RSA");
                return kf.generatePublic(X509publicKey);
            } catch (Exception e) {
                System.out.println("Error: Unable to read from public key file! " + e);
            } 
        }
        return null;
    }

    public void setUID(String uid) throws Exception{
        if(hostname == null | keyFile == null) {
            System.out.println("No UID or File");
            throw new IllegalStateException("User needs to be set");
        }

        String uidLine = uid + System.lineSeparator();
        byte[] publicKeyByte = (kp != null) ? kp.getPublic().getEncoded() : new byte[0];

        try(FileOutputStream fs = new FileOutputStream(keyFile)) {
            fs.write(uidLine.getBytes());
            fs.write(publicKeyByte);

        } catch(Exception e) {
            System.out.println("UID or Public Key issue");
            throw e;
        }

    }

    public String getUID(String user) {
        File uFile = new File(PUBLIC_KEY_DIR + "/" + user + ".txt");
        if(uFile.exists() && uFile.isFile()) {
            try {
                List<String> lines = Files.readAllLines(uFile.toPath());  
                
                if(!lines.isEmpty()) {
                    return lines.get(0).trim();
                }
                } catch(IOException e) {
                    System.out.println("Error: Unable to read UID " + e);
                }
        }

        return null;
    }

}

// Exception for unknown users
class UnknownUser extends Exception {
    public UnknownUser() {
        super();
    }
}