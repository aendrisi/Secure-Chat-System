/* CS6349 Network Security: Secure Relay-Based Chat System
 * By Parisa Nawar (pxn210032) and Aendri Singh (axs210369)
 * 
 * MessageManager Class: Creates or parses a message for communication
 */

import java.io.*;
import java.util.concurrent.*;
import javax.crypto.SecretKey;
import java.net.*;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.time.LocalDateTime;

/**
 * MessageManager encodes and decodes messages between 2 endpoints.
 */
public class MessageManager {
    private final int SESSION_DURATION_MINS = 15;

    private String source;
    private String destination;
   
    private PrivateKey srcPrivKey;
    private PublicKey destPubKey;

    private boolean sessionMode = false; //If a session is active
    private SecretKey sessionKey;
    private int sessionID;
    private LocalDateTime sessionExpiretime;

    /**
     * Creates a MessageManager with an unknown destination public key.
     * @param source Source's name
     * @param srcPrivKey Source's private key 
     * @param destination Destination's name
     * @throws FileNotFoundException Destination's public key could not be found.
     */
    public MessageManager(String source, PrivateKey srcPrivKey, String destination) 
        throws FileNotFoundException
    {
        this.source =  source;
        this.destination =  destination;

        KeyHandler keyhand = new KeyHandler();
        this.srcPrivKey = srcPrivKey;
        destPubKey = keyhand.getUserPublicKey(destination);
        
        // Check if destination public key was found
        if (destPubKey == null) {
            throw new FileNotFoundException("Destination's public key could not be found.");
        }
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
        else {
            decryptData = decryptHashRSA(data);
        }

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
        String ciphertext = plaintext;
        // Encryption: RSA (dest's public key)
        // Key-Hash: Digital Signature (sender's private key)
        return ciphertext;
    }

    //%%% INCOMPLETE %%%//
    /**
     * Encrypts with shared secret key and adds an HMAC to the given plaintext.
     * @param plaintext Plaintext
     * @return Ciphertext
     */
    private String encryptHashSession (String plaintext) {
        String ciphertext = plaintext;
        // Encryption: Secret Key (session key)
        // Key-Hash: HMAC (session key)
        return ciphertext;
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
        String plaintext = ciphertext;
        // Decryption: RSA (dest's public key)
        // Key-Hash: Digital Signature (sender's private key)

        // Verify integrity
        boolean validKeyedHash = false;
        if (!validKeyedHash) { throw new CannotVerifyIntegrity(); }

        return plaintext;
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
        boolean validKeyedHash = false;
        if (!validKeyedHash) { throw new CannotVerifyIntegrity(); }

        return plaintext;
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



