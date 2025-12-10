/* CS6349 Network Security: Secure Relay-Based Chat System
 * By Parisa Nawar (pxn210032) and Aendri Singh (axs210369)
 * 
 * Code for the Relay server
 */

import java.io.*;
import java.util.Base64;
import java.util.HashMap;
import java.util.Random;
import java.util.concurrent.*;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

import java.net.*;
import java.nio.charset.StandardCharsets;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.PublicKey;
import java.security.spec.X509EncodedKeySpec;

public class Server {
    private static final String RELAY_NAME = "Relay";
    private static final int serverPort = 1025;
    private static ConcurrentHashMap<String, ClientHandler> clients = new ConcurrentHashMap<>();
    private static ConcurrentHashMap<Integer, PublicKey> uidKeyMap = new ConcurrentHashMap<>();
    private static ConcurrentHashMap<String, Integer> hostUIDMap = new ConcurrentHashMap<>();
    private static Random random = new Random();
    private static KeyPair kp;

    public static void main(String[] args) throws InterruptedException {
        System.out.println("Server is running");

        // Generate Public and Private Keys
        try {
            kp = KeyHandler.createRSAKeyPair(RELAY_NAME);
            File relayKeyFile = new File("PublicKeys/Relay.txt");
            if (!relayKeyFile.exists()) {
                System.err.println("Cant publish Relay public key");
                return;
            }
        } catch (Exception e) {
            System.out.println("Error: Unable to create key pair! " + e);
            e.printStackTrace();
            return;
        }
        
        // Server running and waiting for clients
        try(ServerSocket serverSocket = new ServerSocket(serverPort)) {
            // Listen for new clients 
            while (!serverSocket.isClosed()) {
                Socket socket = serverSocket.accept();
                System.out.println("A new client has connected.");
                ClientHandler cHandler;
                try {
                    cHandler = new ClientHandler(socket, kp);
                } catch (Exception e) {
                    System.out.println("ERROR: Unable to find client's public key!");
                    continue;
                }

                cHandler.start();
            }

        } catch(IOException e) {
            System.err.println("Exception: " + e.getMessage());
            e.printStackTrace();
        } finally {
            System.out.println("Server terminated");
        }
    }

    /**
     * Registers client with the Relay and returns an UID or returns a client's existing UID.
     * @param hostname Client's identifier name
     * @param encodedPublicKey Client's public key
     * @return UID 
     * @throws Exception
     */
    public static int registerClient(String hostname, String encodedPublicKey) throws Exception {
        // Decode Public Key
        byte[] byteKey = Base64.getDecoder().decode(encodedPublicKey);
        X509EncodedKeySpec X509publicKey = new X509EncodedKeySpec(byteKey);
        KeyFactory kf = KeyFactory.getInstance("RSA");
        PublicKey publicKey = kf.generatePublic(X509publicKey);

        // Search for existing UID
        Integer existingUid = hostUIDMap.get(hostname);
        
        //if uid exists, just return the existing one
        if (existingUid != null) {
            uidKeyMap.put(existingUid, publicKey);
            System.out.println(hostname + " UID found: " + existingUid);
            return existingUid;
        }

        //otherwise create a 5 digit new uid and return 
        int newUid;
        do {
            newUid = 10000 + random.nextInt(90000); // 5 numbers
        } while (uidKeyMap.containsKey(newUid));

        uidKeyMap.put(newUid, publicKey);
        hostUIDMap.put(hostname, newUid);

        return newUid;
    }

    /**
     * Relays the message from a client to the intended receiver.
     * @param msg Message from Client
     */
    public static void relay(Message msg) {
        String sender = msg.getSender();
        String receiver = msg.getReceiver();
        
        ClientHandler receiverHandler = clients.get(receiver);
        // Reciever Found
        if(receiverHandler != null) {
            MessageManager relayToClient = receiverHandler.getRelayToClientManager();
            String msgToReceiver = relayToClient.encodeMessage(
                //Opcode.MESG,
                msg.getOpcode(),
                sender,
                receiver,
                msg.getBody()
            );
            receiverHandler.sendClientMessage(msgToReceiver);
        } 
        // Receiver not found
        else {
            System.out.println("ERROR: Unable to find receiver '" + receiver + "'");
            // %%% SEND ERROR MESSAGE BACK TO SENDER %%%
        }
    }

    /**
     * Handler for server to client communication
     */
    private static class ClientHandler extends Thread {
        private Socket clientSocket;
        private String clientName;

        private PrintWriter out;
        private BufferedReader in;
        private MessageManager relayToClient;

        private KeyPair relayKeys;
        private PublicKey clientKey;
        private SecretKey sessionKey;

        // Session Establishment stages
        enum Stages {
            STAGE1, STAGE2, STAGE3;
        }

        // REGISTRATION
        private int uid = -1;

        // SESSION SETUP
        private Stages stateSESR = Stages.STAGE1;
        private int challenge1 = 0;
        private int challenge2 = KeyHandler.createChallenge();
        KeyPair dfkeyPair;

        /**
         * Creates a client handler with the given socket.
         * @param socket Client to Relay Socket
         * @param relayKeys Relay's Public/Private Key Pair
         */
        public ClientHandler(Socket socket, KeyPair relayKeys) {
            this.clientSocket = socket;
            this.relayKeys = relayKeys;
        }

        /** 
         * DELETE
         * Creates a client handler with the given socket, clientID, and the Relay's public key pair
         * @param socket Client to Relay Socket
         * @param clientName Client username
         * @param keys Relay public key pair
         * @throws UnknownUser
         */
        public ClientHandler(Socket socket, String clientName, KeyPair keys) throws UnknownUser {
            this.clientSocket = socket;
            this.clientName = clientName;
            this.relayKeys = keys;

            clientKey = KeyHandler.findPublicKey(clientName);
        }

        /**
         * Checks for messages from client
         */
        public void run() {
            try {
                out = new PrintWriter(clientSocket.getOutputStream(), true);
                in = new BufferedReader(new InputStreamReader(clientSocket.getInputStream()));
                //relayToClient = new MessageManager(RELAY_NAME, relayKeys.getPrivate());

                String input; 
                String body;
                HashMap<String, String> bodyList;

                while ((input = in.readLine()) != null) {
                    //System.out.println("Received from " + clientID + ": " + input);
                    System.out.println("Line 206 server");
                    Message inputMessage;

                    // Encode message
                    try {
                        System.out.println("Line 209 server");
                        System.out.println("Testing input " + input);
                        //Message inputMessage = new Message(input);
                    if(relayToClient == null) {
                        System.out.println("REGI bootstrap - decrypting without signature check");
                        
                        String[] parts = input.split("\\|\\|");
                        if(parts.length != 3) {
                            throw new InvalidMessageFormat("Expected 3-part encrypted message");
                        }
                        
                        String aesCiphertextB64 = parts[0];
                        String encryptedKeyB64 = parts[1];
                        
                        byte[] encryptedKey = Base64.getDecoder().decode(encryptedKeyB64);
                        Cipher rsaCipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
                        rsaCipher.init(Cipher.DECRYPT_MODE, relayKeys.getPrivate());
                        byte[] messageKeyBytes = rsaCipher.doFinal(encryptedKey);
                        SecretKey messageKey = new SecretKeySpec(messageKeyBytes, "AES");
                        
                        byte[] aesCiphertext = Base64.getDecoder().decode(aesCiphertextB64);
                        Cipher aesCipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
                        aesCipher.init(Cipher.DECRYPT_MODE, messageKey);
                        byte[] plaintextBytes = aesCipher.doFinal(aesCiphertext);
                        String decryptedREGI = new String(plaintextBytes, StandardCharsets.UTF_8);
                        
                        System.out.println("REGI decrypted: " + decryptedREGI.substring(0, 100));
                        inputMessage = new Message(decryptedREGI);
                        clientName = inputMessage.getSender();
                        
                    } else {
                        String decryptedInput = relayToClient.decodeMessage(input).toString();
                        inputMessage = new Message(decryptedInput);
                    }

                    if(inputMessage.getOpcode() == Opcode.SESC || inputMessage.getOpcode() == Opcode.MESG) {
                        ClientHandler receiverHandler = Server.clients.get(inputMessage.getReceiver());
                        String msgToReceiver = null;
                        if(receiverHandler != null && receiverHandler.getRelayToClientManager() != null) {
                            MessageManager relayToReceiver = receiverHandler.getRelayToClientManager();
                            msgToReceiver = relayToReceiver.encodeMessage(
                            inputMessage.getOpcode(),
                            inputMessage.getSender(),
                            inputMessage.getReceiver(),
                            inputMessage.getBody()  
                            );
                        }

                        receiverHandler.sendClientMessage(msgToReceiver);
                        continue;

                    }

                        // REGISTRATION
                        if(inputMessage.getOpcode() == Opcode.REGI) {
                            body = inputMessage.getBody();
                            bodyList = MessageManager.readListBody(body);
                            clientName = inputMessage.getSender();

                            // Get Client's Public Key
                            String encodedPublicKey;
                            if (bodyList.containsKey("Public Key")) {
                                    encodedPublicKey = bodyList.get("Public Key");
                            } else { throw new InvalidMessageFormat(); }

                            // Generate/Locate UID
                            uid = Server.registerClient(clientName, encodedPublicKey);
                            System.out.println("REGI " + clientName + ": new UID " + uid);
                            
                            PublicKey clientPubKey = uidKeyMap.get(uid);
                            if (clientPubKey == null) {
                                throw new UnableToRegister("Client public key not found");
                            }
                            relayToClient = new MessageManager(RELAY_NAME, relayKeys.getPrivate(), clientName, clientPubKey);

                            // Add to the client list
                            clients.put(clientName, this);

                            // Update MessageManager
                            /**relayToClient.setDestination(clientName);

                            if (uidKeyMap.get(uid) != null) {
                                relayToClient.setDestPubKey(uidKeyMap.get(uid));
                            } else {
                                throw new UnableToRegister("UID not found!");
                            }*/

                            // Send Client their UID
                            bodyList.clear();
                            bodyList.put("UID", String.valueOf(uid));

                            String uidMessage = relayToClient.encodeMessage(
                                Opcode.REGI,
                                MessageManager.createListBody(bodyList)
                            );

                            relayToClient.setSource("Relay");
                            relayToClient.setDestination(clientName);
                            out.println(uidMessage);
                            continue;
                            
                        } 
                        // SESSION KEY: Client to Relay
                        else if (inputMessage.getOpcode() == Opcode.SESR) {
                            System.out.println("SESR " + clientName + ":");
                            body = inputMessage.getBody();
                            if (stateSESR == Stages.STAGE1) {
                                // 1. Client -> Relay: Challenge 1
                                System.out.println("- SESR " + clientName + " (1): Client -> Relay");
                                bodyList = MessageManager.readListBody(body);

                                // Get Challenge 1
                                if (bodyList.containsKey("Challenge 1")) {
                                    challenge1 = Integer.parseInt(bodyList.get("Challenge 1"));
                                } else { throw new InvalidMessageFormat(); }

                                // 2. Relay -> Client: Challenge 1 response, Challenge 2, Diffie-Hellman public value
                                System.out.println("- SESR " + clientName + " (2): Relay -> Client");
                                dfkeyPair = KeyHandler.createDHKeyPair(); // create keypair

                                bodyList.clear();
                                bodyList.put("Challenge 1 Response", String.valueOf(challenge1));
                                bodyList.put("Challenge 2", String.valueOf(challenge2));
                                bodyList.put("DF Value", KeyHandler.convertDFPubKeytoString(dfkeyPair.getPublic()));

                                String msgString = relayToClient.encodeMessage(
                                    Opcode.SESR, 
                                    MessageManager.createListBody(bodyList)
                                );

                                out.println(msgString);
                                
                                // Set State
                                stateSESR = Stages.STAGE2; 
                                relayToClient.resetSession(); 
                            } 
                            // 3. Client -> Relay: Challenge 2 response, DF Value
                            else {
                                System.out.println("- SESR " + clientName + " (3): Client -> Relay");
                                bodyList = MessageManager.readListBody(body);

                                // Verify Challenge 2 response
                                if (bodyList.containsKey("Challenge 2 Response")) {
                                    int resp = Integer.parseInt(bodyList.get("Challenge 2 Response"));
                                    if (challenge2 != resp) { throw new CannotVerifyIntegrity(); }
                                } else { throw new InvalidMessageFormat(); }

                                // Get D-F public value
                                if (bodyList.containsKey("DF Value")) {
                                    PublicKey clientDF = KeyHandler.convertStringtoDFPubKey(bodyList.get("DF Value"));
                                    sessionKey = KeyHandler.deriveSessionKey(dfkeyPair.getPrivate(), clientDF); // Derive Session key
                                } else { throw new InvalidMessageFormat(); }
                                
                                System.out.println("SESR " + clientName + ": Session Established");
                                relayToClient.setSession(sessionKey, uid); // SessionID = UID
                                stateSESR = Stages.STAGE1; // Reset state
                            }
                        }
                        // SESSION KEY: Client to Client
                        else if (inputMessage.getOpcode() == Opcode.SESC) {
                            System.out.println("SESC " + clientName + ": Relay " + inputMessage.getSender() + " -> " + inputMessage.getReceiver());
                            Server.relay(inputMessage);
                        }
                        // MESSAGE: Client to Client
                        else if (inputMessage.getOpcode() == Opcode.MESG) {
                            System.out.println("MESG " + clientName + ": Relay " + inputMessage.getSender() + " -> " + inputMessage.getReceiver());
                            Server.relay(inputMessage);
                        }
                        else {
                            System.out.println(inputMessage.getOpcode().toString());
                            Server.relay(inputMessage);
                        }

                    } catch (InvalidMessageFormat e) {
                        System.out.println("ERROR: MESSAGE FORMAT INVALID!");
                        e.printStackTrace();
                        // %%% Error message to client %%%
                    } catch (CannotVerifyIntegrity e) {
                        System.out.println("ERROR: CANNOT VERIFY CLIENT'S INTEGRITY!");
                        String errorMsg = relayToClient.encodeMessage(Opcode.ERSR, "Relay session key expired");
                        out.println(errorMsg);
                        e.printStackTrace();
                        // %%% Error message to client %%%
                    } catch (Exception e) {
                        System.out.println("ERROR: Something else is wrong with the message!");
                        e.printStackTrace();
                    }
                }

            } catch(IOException e) {
                System.err.println("ERROR: " + clientName + " " + e.getMessage());
            } finally {
                try {
                    if(out != null) {
                        out.close();
                    }

                    if(in != null) {
                        in.close();
                    }

                    if (clientSocket != null && !clientSocket.isClosed()) {
                        clientSocket.close();
                    }

                    if(clientName != null) {
                        clients.remove(clientName);
                    }

                } catch(IOException e) {
                    System.err.println(clientName + " " + e.getMessage());
                }
            }
        }

        public void sendClientMessage(String msg) {
            if(out != null) {

                out.println(msg);
            }
        }
    
        /**
         * Returns the MessageManager for Relay to Client 
         * @return MessageManager for Relay to Client 
         */
        public MessageManager getRelayToClientManager() {
            return relayToClient;
        }
    }
}