/* CS6349 Network Security: Secure Relay-Based Chat System
 * By Parisa Nawar (pxn210032) and Aendri Singh (axs210369)
 * 
 * MessageManager Class: Creates or parses a message for communication
 */

import java.io.*;
import java.util.Base64;
import java.util.HashMap;
import java.util.concurrent.*;

import javax.crypto.Cipher;
import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;

import java.net.*;
import java.security.MessageDigest;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Signature;
import java.time.LocalDateTime;

/**
 * MessageManager encodes and decodes messages between 2 endpoints.
 */
public class MessageManager {
    private final int SESSION_DURATION_MINS = 15;
    private static final String BODY_SEPERATOR = "###";
    private static final String VALUE_SEPERATOR = ": ";

    private String source;
    private String destination;
   
    private PrivateKey srcPrivKey;
    private PublicKey destPubKey;

    private boolean sessionMode = false; //If a session is active
    private SecretKey sessionKey;
    private int sessionID;
    private LocalDateTime sessionExpiretime;

    private SecureRandom rand = new SecureRandom();

    /**
     * Creates a MessageManager with an unknown destination.
     * @param source Source's Name
     * @param srcPrivKey Source's Private Key
     */
    public MessageManager(String source, PrivateKey srcPrivKey) {
        this.source = source;
        this.srcPrivKey = srcPrivKey;
    }

    /**
     * Creates a MessageManager with an unknown destination public key.
     * @param source Source's name
     * @param srcPrivKey Source's private key 
     * @param destination Destination's name
     * @throws UnknownUser Destination's public key could not be found.
     */
    public MessageManager(String source, PrivateKey srcPrivKey, String destination) 
        throws UnknownUser
    {
        this.source =  source;
        this.destination =  destination;
        this.srcPrivKey = srcPrivKey;

        destPubKey = KeyHandler.findPublicKey(destination);
    }

    /**
     * Creates a MessageManager.
     * @param source Source's name
     * @param srcPrivKey Source's private key 
     * @param destination Destination's name
     * @param destPubKey Destination's public key
     */
    public MessageManager(String source, PrivateKey srcPrivKey, String destination, PublicKey destPubKey) {
        this.source =  source;
        this.destination =  destination;
        this.srcPrivKey = srcPrivKey;
        this.destPubKey = destPubKey;
    }
    
    /**
     * Sets the destination name
     * @param destination Destination's name
     */
    public void setDestination(String destination) {
        this.destination = destination;
    }

    /**
     * Sets the Destination's public Key
     * @param destPubKey Destination's Public Key
     */
    public void setDestPubKey(PublicKey destPubKey) {
        this.destPubKey = destPubKey;
    }

    /**
     * Activates Session Mode and sets the relevant fields. 
     * @param sessionKey Session key
     * @param sessionID Identifier for current session 
     * @param expiry The expiry time for the session
     */
    public void setSession(SecretKey sessionKey, int sessionID, LocalDateTime expiry) {
        sessionMode = true;
        this.sessionKey = sessionKey;
        this.sessionID = sessionID;
        this.sessionExpiretime = expiry;
    }

    /**
     * Activates Session Mode and sets the relevant fields. Calculates 
     * and returns session expiry time.
     * @param sessionKey Session key
     * @param sessionID Identifier for current session
     */
    public LocalDateTime setSession(SecretKey sessionKey, int sessionID) {
        sessionMode = true;
        this.sessionKey = sessionKey;
        this.sessionID = sessionID;
        this.sessionExpiretime = LocalDateTime.now().plusMinutes(SESSION_DURATION_MINS);

        return sessionExpiretime;
    }

    /**
     * Sets sessionID to given value.
     * @param sessionID Identifier for current session
     */
    public void setSessionID(int sessionID) {
        this.sessionID = sessionID;
    }

    /**
     * Resets the session key by deactivating session mode
     */
    public void resetSession() {
        sessionMode = false;
    }

    /**
     * Creates an encrypted message with no body.
     * @param opcode Message type
     * @return Encrypted message
     */
    public String encodeMessage(Opcode opcode) {
        Message message = new Message(opcode, source, destination);
        if (sessionMode) {message.setSessionID(sessionID); }

        // Encrypt + Hash
        if (sessionMode) { return encryptHashSession(message.toString()); } 
        else { return encryptHashRSA(message.toString()); }
    }

    /**
     * Creates an encrypted message with a body.
     * @param opcode Message type
     * @param body Message body
     * @return Encrypted message
     */
    public String encodeMessage(Opcode opcode, String body) {
        Message message = new Message(opcode, source, destination, body);
        if (sessionMode) {message.setSessionID(sessionID); }
        
        // Encrypt + Hash
        if (sessionMode) { return encryptHashSession(message.toString()); } 
        else { return encryptHashRSA(message.toString()); }
    }

    /**
     * Creates an encrypted message with no body and different sender/receiver.
     * @param opcode Message type
     * @param sender Original source
     * @param receiver Final receipient
     * @return Encrypted message
     */
    public String encodeMessage(Opcode opcode, String sender, String receiver) {
        Message message = new Message(opcode, sender, receiver);
        if (sessionMode) {message.setSessionID(sessionID); }
        
        // Encrypt + Hash
        if (sessionMode) { return encryptHashSession(message.toString()); } 
        else { return encryptHashRSA(message.toString()); }
    }

    /**
     * Creates an encrypted message with a body and different sender/receiver.
     * @param opcode Message type
     * @param sender Original source
     * @param receiver Final receipient
     * @param body Message body
     * @return Encrypted message
     */
    public String encodeMessage(Opcode opcode, String sender, String receiver, String body) {
        Message message = new Message(opcode, sender, receiver, body);
        if (sessionMode) {message.setSessionID(sessionID); }
        
        // Encrypt + Hash
        if (sessionMode) { return encryptHashSession(message.toString()); } 
        else { return encryptHashRSA(message.toString()); }
    }

    //%%% INCOMPLETE %%%//
    /**
     * Parses and decodes the given message and returns the message object
     * @param data
     * @return Message object 
     * @throws Exception Invalid message
     */
    public Message decodeMessage(String data) throws Exception{
        String decryptData;
        if (sessionMode) {
            decryptData = decryptHashSession(data);
        }
        else { decryptData = decryptHashRSA(data); }

        Message message = new Message(decryptData);
        return message;
    }

    //%%% INCOMPLETE %%%//
    /**
     * Encrypts with RSA and adds a digital signature to the given plaintext.
     * @param plaintext Plaintext
     * @return Ciphertext
     */
    private String encryptHashRSA (String plaintext) {
        //String ciphertext = plaintext;
        // Encryption: RSA (dest's public key)
        // Key-Hash: Digital Signature (sender's private key)
        /*try {
            // Digitally sign with sender priv key 
            Signature rsaSig = Signature.getInstance("SHA256withRSA");
            rsaSig.initSign(srcPrivKey);
            rsaSig.update(plaintext.getBytes());
            byte[] digSig = rsaSig.sign();

            // Encrypt message with receiver pub key
            SecretKey secKey = KeyHandler.createAESSecretKey();

            // Encrypt using AES on symmetric key
            Cipher aesCip = Cipher.getInstance("AES/CBC/PKCS5Padding");
            aesCip.init(Cipher.ENCRYPT_MODE, secKey);
            byte[] encData = aesCip.doFinal(plaintext.getBytes());

            // Encrypt key using RSA public key
            Cipher rsaCip = Cipher.getInstance("RSA/ECB/PKCS1Padding");
            rsaCip.init(Cipher.PUBLIC_KEY, destPubKey);
            byte[] encKey = rsaCip.doFinal(secKey.getEncoded());

            // Encode the signature and messages then return the combined RSA
            String encSig = Base64.getEncoder().encodeToString(digSig);
            String encDataString = Base64.getEncoder().encodeToString(encData);
            String encKeyString = Base64.getEncoder().encodeToString(encKey);

            return encDataString + "||" + encKeyString + "||" + encSig;
        } catch(Exception e) {
            System.out.println("RSA encryption failed: " + e.getMessage());
            e.printStackTrace();
            return "";
        }*/

        return plaintext;
    }

    //%%% INCOMPLETE %%%//
    /**
     * Encrypts with shared secret key and adds an HMAC to the given plaintext.
     * @param plaintext Plaintext
     * @return Ciphertext
     */
    private String encryptHashSession (String plaintext) {
        //String ciphertext = plaintext;
        // Encryption: Secret Key (session key)
        // Key-Hash: HMAC (session key)
        //return ciphertext;

        /*try {
            //Convert to bytes and encrypt  
            byte[] plainBytes = plaintext.getBytes();
            //HMAC calculation
            Mac hashMAC = Mac.getInstance("HmacSHA256");
            hashMAC.init(sessionKey);
            byte[] hmacBytes = hashMAC.doFinal(plainBytes);
            //Encode HMAC
            String encodedHMAC = Base64.getEncoder().encodeToString(hmacBytes);

            return plainBytes + "||" + encodedHMAC;
        } catch (Exception e) {
            System.out.println("HMAC Failed: " + e.getMessage());
            return null;
        }   */
       return plaintext;
    }

    //%%% INCOMPLETE %%%//
    /**
     * Decrypts the given plaintext with RSA and verifies the integrity of the 
     * message.
     * @param ciphertext Ciphertext
     * @return Plaintext
     * @throws CannotVerifyIntegrity Message contents have been altered
     */
    private String decryptHashRSA (String ciphertext) throws CannotVerifyIntegrity {
        //String plaintext = ciphertext;
        // Decryption: RSA (dest's public key)
        // Key-Hash: Digital Signature (sender's private key)

        // Verify integrity
        //boolean validKeyedHash = true; //fix later
        //if (!validKeyedHash) { throw new CannotVerifyIntegrity(); }
        //return plaintext;

        /*try {
            //split the ciphertext values from the separator
            String[] cipherVals = ciphertext.split(java.util.regex.Pattern.quote("||"), 2);

            if(cipherVals.length != 2) {
                throw new InvalidMessageFormat("RSA Ciphertext has issues");
            }

            // Decode the data and signature
            byte[] encData = Base64.getDecoder().decode(cipherVals[0]);
            byte[] digSig = Base64.getDecoder().decode(cipherVals[1]);

            boolean validKeyedHash = true; //fix later
            if (!validKeyedHash) { throw new CannotVerifyIntegrity(); }
            return "plaintext";
            // Decrypt with receiver's public key????
            //but i dont have receiver private key here???
        } catch(CannotVerifyIntegrity | InvalidMessageFormat e) {
            throw new CannotVerifyIntegrity("RSA decode fail");
        }*/

        return ciphertext;
    }

    //%%% INCOMPLETE %%%//
    /**
     * Decrypts the given plaintext with a shared secret key and verifies the 
     * integrity of the message.
     * @param ciphertext
     * @return
     * @throws CannotVerifyIntegrity
     */
    private String decryptHashSession (String ciphertext) throws CannotVerifyIntegrity {
        String plaintext = ciphertext;
        // Decryption: Secret Key (session key)
        // Key-Hash: HMAC (session key)

        // Verify integrity
        //boolean validKeyedHash = false;
        //if (!validKeyedHash) { throw new CannotVerifyIntegrity(); }

        //return plaintext;

        /*try {
            String[] hmacVals = ciphertext.split(java.util.regex.Pattern.quote("||"), 2);
            //Calculate HMAC and compare plaintext calc for integrity
            byte[] hmacBytes = Base64.getDecoder().decode(hmacVals[1]);
            Mac verMac = Mac.getInstance("HmacSHA256");
            byte[] verHMACBytes = verMac.doFinal(hmacVals[0].getBytes());

            if(!MessageDigest.isEqual(hmacBytes, verHMACBytes)) {
                throw new CannotVerifyIntegrity("HMAC validation failed");
            }
            
            return "";
        } catch(Exception e) {
            throw new CannotVerifyIntegrity("HMAC verification failed");
        }*/

        return ciphertext;
    }

    /**
     * Creates a message body from a given list of header-value pairs.
     * @param list
     * @return
     */
    public static String createListBody(HashMap<String, String> list){
        String body = "";
        if (list.isEmpty()) { return body; }

        for (String header : list.keySet()) {
            body += header + VALUE_SEPERATOR + list.get(header) + BODY_SEPERATOR;
        }
        return body.substring(0, body.length() - BODY_SEPERATOR.length());
    }

    /**
     * Returns a hashmap from a given message body list
     * @param body
     * @return
     * @throws Exception
     */
    public static HashMap<String, String> readListBody(String body) throws Exception{
        HashMap<String, String> list = new HashMap<>();
        String[] sections = body.split(BODY_SEPERATOR);

        for (String line : sections) {
            String[] values = line.split(VALUE_SEPERATOR);
            list.put(values[0], values[1]);
        }
        return list;
    }

    /**
     * Returns the destination.
     * @return Destination name
     */
    public String getDestination() {
        return destination;
    }

    /**
     * Returns the source.
     * @return Source name
     */
    public String getSource() {
        return source;
    }

    /**
     * Returns true if a session is established, false otherwise.
     * @return sessionMode
     */
    public Boolean isSessionActive() {
        return sessionMode;
    }
}



/**
 * Exception if invalid hash.
 */
class CannotVerifyIntegrity extends Exception {
    /**
     * Exception if invalid hash.
     */
    public CannotVerifyIntegrity() {
        super();
    }

    /**
     * Exception if invalid hash.
     * @param m Display message
     */
    public CannotVerifyIntegrity(String m) {
        super(m);
    }
}

/**
 * Exception if user's public keys cannot be found.
 */
class UnknownUser extends Exception {
    public UnknownUser() {
        super();
    }

    public UnknownUser(String m) {
        super(m);
    }
}

class UnableToRegister extends Exception {
    public UnableToRegister() {
        super();
    }

    public UnableToRegister(String m) {
        super(m);
    }
}


