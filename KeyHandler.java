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
import java.rmi.server.ExportException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.spec.X509EncodedKeySpec;
import java.util.*;
import javax.crypto.KeyAgreement;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

import javax.crypto.KeyAgreement;

public class KeyHandler {
    private final static String PUBLIC_KEY_DIR = "PublicKeys";
    private final static String RELAY_NAME = "Relay";
    private final static int KEY_SIZE = 1024;
    private final static int CHALLENGE_BOUND = 2048;

    /**
     * Creates and publishes a public and private key pair for the given user.
     * @param username Username
     * @return Public and Private key pair
     * @throws Exception Unable to create key pair or publish key pair
     */
    public static KeyPair createRSAKeyPair(String username) throws Exception {
        KeyPair kp;
        // Generate key pair
        try {
            KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
            kpg.initialize(KEY_SIZE); 
            kp = kpg.generateKeyPair();
        } catch (Exception e) {
            System.out.println("Error: Unable to create key pair! " + e);
            throw e;
        }

        // Write to file
        try {
            File keyFile = new File(PUBLIC_KEY_DIR + "/" + username + ".txt");
            Files.write(keyFile.toPath(), kp.getPublic().getEncoded());
        } catch (Exception e) {
            System.out.println("Error: Unable to publish public key! " + e);
            throw e;
        } 

        return kp;
    }

    /**
     * Deletes the user's public key file. Used for cleaning up public
     * key files.
     * @param username Username
     */
    public static void deletePublicKey(String username) {
        File keyFile = new File(PUBLIC_KEY_DIR + "/" + username + ".txt");
        keyFile.delete();
    }
    
    /**
     * Returns a list of all available clients based on the public 
     * key files contained in the directory. 
     * @return list of all available users
     */
    public static List<String> getAvailableUsers() {
        File directory = new File(PUBLIC_KEY_DIR);
        File[] files = directory.listFiles();
        List<String> users = new ArrayList<>();

        // Add names to list
        if (files != null) {
            for (File file : files) {
                String name = file.getName().substring(0, file.getName().length()-4);
                if (!name.equals(RELAY_NAME)) {
                    users.add(name);
                }
            }
        }
        return users;
    }

    /**
     * Searches for the given user's public key and returns either the key or an
     * exception.
     * @param username User to search for
     * @return User's public key OR UnknownUser
     * @throws UnknownUser User's public key could not be found
     */
    public static PublicKey findPublicKey (String username) throws UnknownUser {
        File userFile = new File(PUBLIC_KEY_DIR + "/" + username + ".txt");

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
        throw new UnknownUser();
    }
    
    /**
     * Creates and returns a Diffie-Hellman key pair (global parameters).
     * @return Diffie-Hellman key pair
     * @throws NoSuchAlgorithmException Unable to find algorithm
     */
    public static KeyPair createDHKeyPair() throws NoSuchAlgorithmException {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("DiffieHellman");
        kpg.initialize(KEY_SIZE);
        return kpg.generateKeyPair();
    }

    /**
     * Derives and returns session key from Diffie-Hellman keys.
     * @param userKey User's private Diffie-Hellman key
     * @param targetKey Target's public Diffie-Hellman key
     * @return Session key
     * @throws Exception Error with creating session key
     */
    public static SecretKey deriveSessionKey(PrivateKey userKey, PublicKey targetKey) 
        throws Exception
    {
        KeyAgreement keyAgreement = KeyAgreement.getInstance("DiffieHellman");
        keyAgreement.init(userKey);
        keyAgreement.doPhase(targetKey, true); 
        byte[] sharedSecretBytes = keyAgreement.generateSecret();

        return new SecretKeySpec(sharedSecretBytes, 0, sharedSecretBytes.length, "AES");
    }

    /**
     * Creates and returns a challenge value.
     */
    public static int createChallenge() {
        SecureRandom rand = new SecureRandom();
        return rand.nextInt(CHALLENGE_BOUND);
    }

}