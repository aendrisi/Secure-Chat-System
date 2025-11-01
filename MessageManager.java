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

public class MessageManager {
    private String source;
    private String destination;
   
    private PrivateKey srcKey;
    private PublicKey destKey;

    private boolean sessionMode = false;
    private SecretKey sessionKey;
    private int sessionID;
    private LocalDateTime sessionExpiretime;

    // No public Key
    public MessageManager(String source, PrivateKey srcKey, String destination) 
        throws FileNotFoundException
    {
        this.source =  source;
        this.destination =  destination;

        KeyHandler keyhand = new KeyHandler();
        this.srcKey = srcKey;
        destKey = keyhand.getUserPublicKey(destination);
        
        // Check if destination public key was found
        if (destKey == null) {
            throw new FileNotFoundException();
        }
    }

    // With public key
    public MessageManager(String source, PrivateKey srcKey, String destination, PublicKey destKey) 
        throws FileNotFoundException
    {
        this.source =  source;
        this.destination =  destination;

        this.srcKey = srcKey;
        this.destKey = destKey;
    }
    
    // Sets the session key, sessionID, and activates session mode for messages
    public void setSession(SecretKey sessionKey, int sessionID) {
        this.sessionKey = sessionKey;
        this.sessionID = sessionID;
        sessionMode = true;
    }

    // Resets the session key by deactivating session mode
    public void resetSession() {
        sessionMode = false;
    }

    // Creates an encrypted message NO body
    public String encodeMessage(Opcode opcode) {
        Message message = new Message(opcode, source, destination);
        if (sessionMode) {message.setSessionID(sessionID); }
        return message.toString(); // *** NEED TO ENCRYPT
    }

    // Creates an encrypted message WITH body
    public String encodeMessage(Opcode opcode, String body) {
        Message message = new Message(opcode, source, destination, body);
        if (sessionMode) {message.setSessionID(sessionID); }
        return message.toString(); // *** NEED TO ENCRYPT
    }

    // Creates an encrypted message NO body and different sender/receiver
    public String encodeMessage(Opcode opcode, String sender, String receiver) {
        Message message = new Message(opcode, sender, receiver);
        if (sessionMode) {message.setSessionID(sessionID); }
        return message.toString(); // *** NEED TO ENCRYPT
    }

    // Creates an encrypted message WITH body and different sender/receiver
    public String encodeMessage(Opcode opcode, String sender, String receiver, String body) {
        Message message = new Message(opcode, sender, receiver, body);
        if (sessionMode) {message.setSessionID(sessionID); }
        return message.toString(); // *** NEED TO ENCRYPT
    }

    // Parses the given message and returns a message object
    public Message decodeMessage(String data) throws Exception{
        // *** NEED TO DECRYPT
        Message message = new Message(data);
        return message;
    }


}



