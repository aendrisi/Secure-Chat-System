/* CS6349 Network Security: Secure Relay-Based Chat System
 * By Parisa Nawar (pxn210032) and Aendri Singh (axs210369)
 * 
 * MessageManager Class: Creates or parses a message for communication
 */

import java.io.*;
import java.util.Arrays;
import java.util.Base64;
import java.util.HashMap;
import java.util.concurrent.*;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import java.net.*;
import java.nio.charset.StandardCharsets;
import java.time.LocalDateTime;

import java.security.*;

/**
 * MessageManager encodes and decodes messages between 2 endpoints.
 */
public class MessageManager {
    private final int SESSION_DURATION_MINS = 1;
    private static final String BODY_SEPERATOR = "###";
    private static final String VALUE_SEPERATOR = ": ";

    private final int KEY_IV_ENCODED_SIZE = 172;

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
     * Sets the source name
     * @param source Source name
     */
    public void setSource(String source) {
        this.source = source;
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

    /**
     * Parses and decodes the given message and returns the message object
     * @param data
     * @return Message object 
     * @throws Exception Invalid message
     */
    public Message decodeMessage(String data) throws Exception{
        String decryptData;
        //System.out.println(source + " -> " + destination + ": " + sessionMode);

        if (sessionMode) {
            try {
                decryptData = decryptHashSession(data);
            } catch (Exception e) {
                resetSession();
                decryptData = decryptHashRSA(data);
            }
            
        }
        else { decryptData = decryptHashRSA(data); }

        Message message = new Message(decryptData);
        
        // Set up public keys!
        if (message.getOpcode() == Opcode.REGI && this.destPubKey == null) {
            this.destination = message.getSender();
            this.destPubKey = KeyHandler.findPublicKey(message.getSender());
        }

        return message;
    }

    //%%% INCOMPLETE %%%//
    /**
     * Encrypts with RSA and adds a digital signature to the given plaintext.
     * @param plaintext Plaintext
     * @return Ciphertext
     */
    private String encryptHashRSA (String plaintext) {
        try {
            //temporary AES key
            KeyGenerator keyGen = KeyGenerator.getInstance("AES");
            keyGen.init(256);
            SecretKey msgKey = keyGen.generateKey();

            //encrypted data (temp key)
            Cipher aesCipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
            SecureRandom IVrandomizer = new SecureRandom();
            aesCipher.init(Cipher.ENCRYPT_MODE, msgKey, IVrandomizer);
            byte[] plaintextBytes = plaintext.getBytes(StandardCharsets.UTF_8);
            byte[] aesCiphertext = aesCipher.doFinal(plaintextBytes);
            String aesCiphertextB64 = Base64.getEncoder().encodeToString(aesCiphertext);

            //encrypted temp key (pub key) - 172 chars
            Cipher rsaCipher = Cipher.getInstance("RSA/ECB/PKCS1Padding ");
            rsaCipher.init(Cipher.ENCRYPT_MODE, destPubKey);
            byte[] encryptedKey = rsaCipher.doFinal(msgKey.getEncoded());
            String encryptedKeyB64 = Base64.getEncoder().encodeToString(encryptedKey);

            //encrypted IV (pub key) - 172 chars
            byte[] encryptedIV = rsaCipher.doFinal(aesCipher.getIV());
            String encryptedIVB64 = Base64.getEncoder().encodeToString(encryptedIV);

            // Packet Data = [Temp Key] [IV] [Data] 
            String packetData = encryptedKeyB64 + encryptedIVB64 + aesCiphertextB64;

            //hash of  encrypted data (digital signature - priv key)
            Signature sig = Signature.getInstance("SHA256withRSA");
            sig.initSign(srcPrivKey);
            sig.update(packetData.getBytes(StandardCharsets.UTF_8));
            byte[] sigBytes = sig.sign();
            String sigB64 = Base64.getEncoder().encodeToString(sigBytes);

            //combine the packets to send
            // {[Temp Key] [IV] [Data]} [Sign]
            return packetData + sigB64;

        } catch (Exception e) {
            throw new RuntimeException("encryptHashRSA failed", e); 
        }
    }

    /**
     * Encrypts with shared secret key and adds an HMAC to the given plaintext.
     * @param plaintext Plaintext
     * @return Ciphertext
     */
    private String encryptHashSession (String plaintext) {
        try {
            // {[IV] [Data]} [HMAC]

            //encrypted data (session key)
            Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
            cipher.init(Cipher.ENCRYPT_MODE, sessionKey, new SecureRandom());
            byte[] plainTextBytes = plaintext.getBytes(StandardCharsets.UTF_8);
            byte[] ciphertextBytes = cipher.doFinal(plainTextBytes);
            String ciphertextB64 = Base64.getEncoder().encodeToString(ciphertextBytes);

            //encrypted IV (pub key) - 172 chars
            Cipher ivCipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
            ivCipher.init(Cipher.ENCRYPT_MODE, sessionKey);
            byte[] encryptedIV = ivCipher.doFinal(cipher.getIV());
            String encryptedIVB64 = Base64.getEncoder().encodeToString(encryptedIV);

            //combine IV + data
            byte[] data = new byte[encryptedIV.length + ciphertextBytes.length];
            System.arraycopy(encryptedIV, 0, data, 0, encryptedIV.length);
            System.arraycopy(ciphertextBytes, 0, data, encryptedIV.length, ciphertextBytes.length);

            //generate HMAC
            Mac hmac = Mac.getInstance("HmacSHA256");
            hmac.init(new SecretKeySpec(sessionKey.getEncoded(), "HmacSHA256"));
            byte[] hmacBytes = hmac.doFinal(data);
            String hmacB64 = Base64.getEncoder().encodeToString(hmacBytes);

            return encryptedIVB64 + ciphertextB64 + hmacB64;

        } catch (Exception e) {
            e.printStackTrace();
            throw new RuntimeException("encryptHashSession failed", e); 
        }

    }

    //%%% INCOMPLETE %%%//
    /**
     * Decrypts the given plaintext with RSA and verifies the integrity of the 
     * message.
     * @param ciphertext Ciphertext
     * @return Plaintext
     * @throws CannotVerifyIntegrity 
     */
    String decryptHashRSA(String ciphertext) throws CannotVerifyIntegrity {
        try {
            // {[Temp Key] [IV] [Data]} [Sign]
            String encryptedKeyB64 = ciphertext.substring(0, KEY_IV_ENCODED_SIZE); // TEMP KEY
            String encryptedIVB64 = ciphertext.substring(KEY_IV_ENCODED_SIZE, 2 * KEY_IV_ENCODED_SIZE); // IV
            String encryptedData = ciphertext.substring(2 * KEY_IV_ENCODED_SIZE, ciphertext.length() - KEY_IV_ENCODED_SIZE); // DATA
            String signature = ciphertext.substring(ciphertext.length() - KEY_IV_ENCODED_SIZE); // SIGN

            Cipher rsaCipher = Cipher.getInstance("RSA/ECB/PKCS1Padding ");
            Cipher aesCipher = Cipher.getInstance("AES/CBC/PKCS5Padding");

            // Decrypt Key
            byte[] encryptedKey = Base64.getDecoder().decode(encryptedKeyB64);
            rsaCipher.init(Cipher.DECRYPT_MODE, srcPrivKey);   
            byte[] messageKeyBytes = rsaCipher.doFinal(encryptedKey);
            SecretKey messageKey = new SecretKeySpec(
                Arrays.copyOfRange(messageKeyBytes, messageKeyBytes.length - 32, messageKeyBytes.length),
                "AES");

            // Decrypt IV
            byte[] encryptedIV = Base64.getDecoder().decode(encryptedIVB64);
            rsaCipher.init(Cipher.DECRYPT_MODE, srcPrivKey);   
            byte[] messageIVBytes = rsaCipher.doFinal(encryptedIV);
            IvParameterSpec ivSpec = new IvParameterSpec(
                Arrays.copyOfRange(messageIVBytes, messageIVBytes.length - 16, messageIVBytes.length));

            // Decrypt Data
            byte[] dataPlaintext = Base64.getDecoder().decode(encryptedData);
            aesCipher.init(Cipher.DECRYPT_MODE, messageKey, ivSpec);
            byte[] dataPlaintextBytes = aesCipher.doFinal(dataPlaintext);
            String plaintext = new String(dataPlaintextBytes, StandardCharsets.UTF_8);

            // Verify Packet Size
            Message tempMsg = new Message(plaintext);  
            if (plaintext.length() != tempMsg.getExpectedMessageSize()) {
                throw new InvalidMessageFormat("Message size mismatch.");
            }
            
            // Verifying Signature
            if (destPubKey == null) {
                destPubKey = KeyHandler.findPublicKey(tempMsg.getSender());
            }

            String packetData =  encryptedKeyB64 + encryptedIVB64 + encryptedData;
            
            byte[] sigBytes = Base64.getDecoder().decode(signature);
            Signature sig = Signature.getInstance("SHA256withRSA");
            sig.initVerify(destPubKey);
            sig.update(packetData.getBytes(StandardCharsets.UTF_8));

            if (!sig.verify(sigBytes)) {
                throw new CannotVerifyIntegrity("Invalid RSA signature from " + destination);
            }

            System.out.println("Signature verified for " + destination);
            return plaintext;

        } catch(CannotVerifyIntegrity e) {
            throw e;
        } catch(Exception e) {
            e.printStackTrace();
            throw new CannotVerifyIntegrity("decryptHashRSA failed: " + e.getMessage());
        }
    }
    

    /**
     * Decrypts the given plaintext with a shared secret key and verifies the 
     * integrity of the message.
     * @param ciphertext
     * @return
     * @throws CannotVerifyIntegrity
     */
    private String decryptHashSession (String ciphertext) throws CannotVerifyIntegrity {
        try {
            // {[Temp Key] [IV] [Data]} [Sign]
            int ivHmacSize = 44;
            int cipherLen = ciphertext.length();

            // Get values
            String encryptedIVB64 = ciphertext.substring(0, ivHmacSize);
            String ciphertextB64 = ciphertext.substring(ivHmacSize, cipherLen - ivHmacSize);
            String hmacB64 = ciphertext.substring(cipherLen - ivHmacSize);

            byte[] ciphertextBytes = Base64.getDecoder().decode(ciphertextB64);
            byte[] encryptedIV = Base64.getDecoder().decode(encryptedIVB64);
            byte[] hmacBytes = Base64.getDecoder().decode(hmacB64);

            // Combine IV + data
            byte[] data = new byte[encryptedIV.length + ciphertextBytes.length];
            System.arraycopy(encryptedIV, 0, data, 0, encryptedIV.length);
            System.arraycopy(ciphertextBytes, 0, data, encryptedIV.length, ciphertextBytes.length);

            // Check HMAC
            Mac hmac = Mac.getInstance("HmacSHA256");
            hmac.init(new SecretKeySpec(sessionKey.getEncoded(), "HmacSHA256"));
            byte[] computedHmac = hmac.doFinal(data);

            if (!Arrays.equals(computedHmac, hmacBytes)) {
                throw new CannotVerifyIntegrity("HMAC verification failed");
            }

            // Decrypt IV
            Cipher ivCipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
            ivCipher.init(Cipher.DECRYPT_MODE, sessionKey);   
            byte[] messageIVBytes = ivCipher.doFinal(encryptedIV);
            IvParameterSpec ivSpec = new IvParameterSpec(
                Arrays.copyOfRange(messageIVBytes, messageIVBytes.length - 16, messageIVBytes.length));

            // Decrypt Ciphertext
            Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
            cipher.init(Cipher.DECRYPT_MODE, sessionKey, ivSpec);
            byte[] plaintextBytes = cipher.doFinal(ciphertextBytes);

            return new String(plaintextBytes, StandardCharsets.UTF_8);

        } catch(CannotVerifyIntegrity e) {
            e.printStackTrace();
            throw e;
        } catch(IllegalArgumentException e) {
            throw e;
        } catch(Exception e) {
            e.printStackTrace();
            throw new CannotVerifyIntegrity("decryptHashSession failed " + e.getMessage());
        }
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
     * Parses a given list body to get the values for the expected values
     * @param list List Body 
     * @param expected List of expected keys
     * @return List of values in order of expected keys
     * @throws Exception
     */
    public static String[] parseListBody(HashMap<String, String> list, String[] expected) throws Exception {
        String[] values = new String[expected.length];

        for (int i = 0; i < expected.length; i++) {
            if (list.containsKey(expected[i])) {
                values[i] = list.get(expected[i]);
            } else { throw new InvalidMessageFormat("Missing " + expected[i]); }
        }

        return values;
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
     * Returns true if a session is established and not expired, false otherwise.
     * @return sessionMode
     */
    public Boolean isSessionActive() {
        //check for session mode
        if(!sessionMode) {
            return false;
        }

        //check expiry time 
        if(sessionExpiretime.isBefore(LocalDateTime.now())) {
            System.out.println("[Session has expired]");
            resetSession();
            return false;
        }

        return true;
    }
}

/**
 * Manage session setup between client-relay and client-client
 */
class SessionSetup {
    enum State { NO_SESSION, PROCESSING, SESSION; }
    enum SetupType { REQUEST, RESPONSE; }

    private State state = State.NO_SESSION;
    private SetupType type;

    private KeyPair dhKeyPair;
    private PublicKey targetDF;
    private int challenge1;
    private int challenge2;
    private SecretKey sessionKey;
    
    public SessionSetup() {
        this.type = SetupType.RESPONSE;
        resetSession();
    }

    /**
     * Resets all values
     * @throws NoSuchAlgorithmException
     */
    private void resetValues() {
        try {
            this.dhKeyPair = KeyHandler.createDHKeyPair();
        } catch (NoSuchAlgorithmException e) { e.printStackTrace(); }
        
        this.targetDF = null;

        if (type == SetupType.REQUEST) {
            this.challenge1 = KeyHandler.createChallenge();
            this.challenge2 = 0;
        } else {
            this.challenge1 = 0;
            this.challenge2 = KeyHandler.createChallenge();
        }
        
        this.sessionKey = null;
    }

    /**
     * Restarts the session to not established
     */
    public void resetSession() {
        this.state = State.NO_SESSION;
        resetValues();
    }

    /**
     * Returns the the current state 
     * @return Current State
     */
    public State getState() {
        return state;
    }

    /**
     * Returns the secret key if a session has been established
     * @return Diffie-Hellman secret key
     */
    public SecretKey getKey() {
        if (state == State.SESSION) { return sessionKey; }
        else { return null; }
    }

    /**
     * Creates a returns an encoded client-relay session setup message
     * @param body
     * @param messager
     * @return
     */
    public static String createMessage(String body, MessageManager messager) {
        return messager.encodeMessage(
            Opcode.SESR,  
            body
        );
    }

    /**
     * Parses the given relay message, checks if it's for session establishment
     * @param msg
     * @param messager
     * @return
     */
    public static HashMap<String, String> parseMessage(Message msg, MessageManager messager) throws Exception{
        // Check opcode
        if (msg.getOpcode() != Opcode.SESR) {
            throw new InvalidMessageFormat("Expecting Relay Session Establishment");
        }

        return MessageManager.readListBody(msg.getBody());
    }

    /**
     * Creates a returns an encoded client-client session setup message
     * @param body
     * @param messagerRelay
     * @param messagerClient
     * @return
     */
    public static String createMessage(String body, MessageManager messagerRelay, MessageManager messagerClient) {
        String innerMsgString = messagerClient.encodeMessage(
                Opcode.SESC,
                body
        );

        return messagerRelay.encodeMessage(
                Opcode.SESC,  
                messagerClient.getSource(),
                messagerClient.getDestination(),
                innerMsgString
            );
    }

    /**
     * Given a session establishment message, it returns the next message to be sent
     * @param inputList Parsed list from input
     * @return Next message to be sent, empty values indicate session has been established (response)
     * @throws Exception
     */
    public String nextStep(HashMap<String, String> inputList) throws Exception {
        HashMap<String, String> outputList = new HashMap<>();
        
        // New session establishment
        if (state == State.NO_SESSION || state == State.SESSION) {
            type = SetupType.RESPONSE;
            resetSession();
            System.out.println("[Reset Session]");
        }

        // REQUEST
        if (type == SetupType.REQUEST) {
            switch (state) {
                case SESSION:
                    throw new UnknownSessionEstablishmentState("Wrong state!");
                case NO_SESSION: 
                    throw new UnknownSessionEstablishmentState("Wrong state!");
                case PROCESSING: 
                    // 2. SRC <- DST (Request): Challenge 1 Response, Challenge 2, D-F Public Values
                    System.out.println("+ Session Setup Request (2): Dest -> Source");
                    String [] values = {"Challenge 1 Response", "Challenge 2", "DF Value"};
                    values = MessageManager.parseListBody(inputList, values);

                    // Verify Challenge 1 Response
                    if (challenge1 != Integer.parseInt(values[0])) {
                        throw new CannotVerifyIntegrity("Challenge 1 Response mismatch. Authentication failed.");
                    }

                    // Challenge 2
                    challenge2 = Integer.parseInt(values[1]);

                    // Derive session key
                    targetDF = KeyHandler.convertStringtoDFPubKey(values[2]);
                    sessionKey = KeyHandler.deriveSessionKey(dhKeyPair.getPrivate(), targetDF);

                    // 3. SRC -> DST (Request): Challenge 2 Response, DF Value
                    System.out.println("+ Session Setup Request (3): Source -> Dest");
                    outputList.put("Challenge 2 Response", String.valueOf(challenge2));
                    outputList.put("DF Value", KeyHandler.convertDFPubKeytoString(dhKeyPair.getPublic()));
                    state = State.SESSION;
                    return MessageManager.createListBody(outputList);
            }   
        }
        // RESPONSE
        else if (type == SetupType.RESPONSE) {
            switch (state) {
                case SESSION:
                    throw new UnknownSessionEstablishmentState("Wrong state!");
                case NO_SESSION: 
                    // 1. SRC <- DST (Response): Challenge 1
                    System.out.println("+ Session Setup Response (1): Dest -> Source");
                    String [] values1 = {"Challenge 1"};
                    values1 = MessageManager.parseListBody(inputList, values1);
                    challenge1 = Integer.parseInt(values1[0]);

                    // 2. SRC -> DST (Response): Challenge 1 response, Challenge 2, Diffie-Hellman public value
                    System.out.println("+ Session Setup Response (2): Source -> Dest");
                    outputList.put("Challenge 1 Response", String.valueOf(challenge1));
                    outputList.put("Challenge 2", String.valueOf(challenge2));
                    outputList.put("DF Value", KeyHandler.convertDFPubKeytoString(dhKeyPair.getPublic()));
                    
                    state = State.PROCESSING;
                    return MessageManager.createListBody(outputList);

                case PROCESSING: 
                    // 3. SRC <- DST (Response): Challenge 2 response, DF Value
                    System.out.println("+ Session Setup Response (3): Dest -> Source");
                    String [] values2 = {"Challenge 2 Response", "DF Value"};
                    values2 = MessageManager.parseListBody(inputList, values2);

                    // Verify Challenge 2 Response
                    if (challenge2 != Integer.parseInt(values2[0])) {
                        throw new CannotVerifyIntegrity("Challenge 2 Response mismatch. Authentication failed.");
                    }

                    // Derive session key
                    targetDF = KeyHandler.convertStringtoDFPubKey(values2[1]);
                    sessionKey = KeyHandler.deriveSessionKey(dhKeyPair.getPrivate(), targetDF);

                    state = State.SESSION;
                    return "";
            }  
        } else { throw new UnknownSessionEstablishmentState("Wrong state!"); }
        return "";
    }


    /**
     * 1st step of session setup (Requesting side)
     * @return
     * @throws Exception
     */
    public String requestSession() throws Exception{
        type = SetupType.REQUEST;
        if (state != State.NO_SESSION) { System.out.println("[Restarting Session Setup]"); }
        resetSession();

        System.out.println("+ Session Setup Request (1): Source -> Dest");
        HashMap<String, String> list = new HashMap<>();
        list.put("Challenge 1", String.valueOf(challenge1));

        state = State.PROCESSING; // Next state

        return MessageManager.createListBody(list);
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

/**
 * Exception if Session Establishment is in progress
 */
class UnknownSessionEstablishmentState extends Exception {
    public UnknownSessionEstablishmentState() {
        super();
    }

    public UnknownSessionEstablishmentState(String m) {
        super(m);
    }
}