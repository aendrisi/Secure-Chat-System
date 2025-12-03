/* CS6349 Network Security: Secure Relay-Based Chat System
 * By Parisa Nawar (pxn210032) and Aendri Singh (axs210369)
 * 
 * Code for the clients
 */

import java.io.*;
import java.util.concurrent.*;

import javax.crypto.KeyAgreement;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

import java.net.*;
import java.nio.file.Files;
import java.util.Scanner;
import java.security.*;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import java.util.List;
import java.util.HashMap;

public class Client {
    // Session Establishment stages
    enum Stages {
        NO_SESSION, STAGE1_REQUEST, STAGE2_REQUEST, STAGE1_RESPONSE, STAGE2_RESPONSE, SESSION;
    }
    private static final String RELAY_NAME = "Relay";
    private static final String serverHost = "localhost";
    private static final int serverPort = 1025; 

    private static MessageManager messagerToRelay;
    private static MessageManager messagerToClient;
    private static HashMap<String, MessageManager> clients = new HashMap<>();

    private static String hostName;
    private static int uid;

    private static int sessionID;

    private static PrintWriter serverOut;

    private static KeyPair kp;
    private static Stages clientSessionState = Stages.NO_SESSION;


    public static void main(String[] args) {
        Scanner scan = new Scanner(System.in);

        // Get user's name
        System.out.print("Enter your username (no spaces): ");
        hostName = scan.next();
        if (scan.hasNextLine()) { scan.nextLine(); } // Clear buffer

        // Create an RSA key pair
        try {
            kp = KeyHandler.createRSAKeyPair(hostName);
        } catch (Exception e) {
            System.out.println("Error: Unable to create key pair!");
            scan.close();
            return;
        }

        // Connect to server
        try (
            Socket socket = new Socket(serverHost, serverPort);
            PrintWriter out = new PrintWriter(socket.getOutputStream(), true);
            BufferedReader in = new BufferedReader(new InputStreamReader(socket.getInputStream()));
        ) {
            serverOut = out;
            MessageHandler messageHandler = new MessageHandler(in, out);
            String sendingMessage;
            String receivingMessage;
            HashMap<String, String> list = new HashMap<>();; 

            // MessageManager for User to Relay communication
            try {
                messagerToRelay = new MessageManager(hostName, kp.getPrivate(), RELAY_NAME);
            } catch (Exception e) {
                System.out.println("Unable to locate Relay server's public key! " + e);
                scan.close();
                KeyHandler.deletePublicKey(hostName);
                return;
            }
            
            // STAGE 1: Registration -----------------------------------------------------------------
            System.out.println("REGISTRATION STAGE");
            String encodedPublicKey = Base64.getEncoder().encodeToString(kp.getPublic().getEncoded());

            // 1. Client -> Relay: Registration with public key
            list.clear(); 
            list.put("Public Key", encodedPublicKey);

            sendingMessage = messagerToRelay.encodeMessage(
                Opcode.REGI,
                MessageManager.createListBody(list) // Public Key: [key]
            );

            out.println(sendingMessage); 

            // 2. Relay -> Client: Registration UID
            receivingMessage = in.readLine(); 

            // Parse message for UID
            if(receivingMessage != null) {
                String trimmedResponse = receivingMessage.trim();
                try {
                    Message uidResponse = messagerToRelay.decodeMessage(trimmedResponse);
                    if (uidResponse.getOpcode() == Opcode.REGI) {
                        String uidBody = uidResponse.getBody();
                        list = MessageManager.readListBody(uidBody);

                        // Get UID
                        if (list.containsKey("UID")) {
                            uid = Integer.parseInt(list.get("UID"));
                        } else { throw new InvalidMessageFormat(); }

                        System.out.println("Registration successful. UID: " + uid);
                        
                    } else {
                        System.out.println("Registration failed: unexpected Opcode: " + uidResponse.getOpcode());
                        scan.close();
                        return;
                    }
                } 
                catch (NumberFormatException e) {
                    System.out.println("Registration failed: invalid UID format");
                    scan.close();
                    return;
                }
                catch (Exception e) {
                    System.out.println("Registration failed: Failed to decode response");
                    e.printStackTrace();
                    System.out.println(e.getMessage());
                    scan.close();
                    return;
                }      
            } else {
                System.out.println("Registration failed: null response");
                scan.close();
                return;
            }

            //continue the buffer
            try {
                if(in.ready()) {
                    while (in.ready()) {
                        in.readLine();
                    }
                }
                Thread.sleep(100);
            } catch(Exception e) {
                e.printStackTrace();
            }

            // STAGE 2.1: Authentication and Session Setup with RELAY ---------------------------------------
            try {
                AuthSessiontoRelay(out, in);
            } catch (Exception e) {
                System.out.println ("Unable to authenticate to relay!");
                e.printStackTrace();
            }
            
            // Stage 2.15: CHOSING A CLIENT! ----------------------------------------------------------------
            messagerToClient = chooseDest(scan); 
            // verify destination was chosen
            if (messagerToClient == null) {
                scan.close();
                KeyHandler.deletePublicKey(hostName);
                return;
            }

            // Stage 2.5: Session Establishment
            try {
                if (in.ready()) {
                    String msgString = in.readLine().trim();
                    Message outerMsg = messagerToRelay.decodeMessage(msgString);
                    
                    // Setup Client Session:
                    if (outerMsg.getOpcode() == Opcode.SESC) {
                        Message innerMsg = messagerToRelay.decodeMessage(outerMsg.getBody());
                        if (innerMsg.getOpcode() == Opcode.SESC) {
                            AuthSessiontoClientResponse(out, in, innerMsg);
                        } else {
                            throw new InvalidMessageFormat("Unknown Opcode (expecting SESC): " + innerMsg.getOpcode());
                        }

                    }   
                } else {
                    AuthSessiontoClientRequest(out, in);
                }
            } catch (Exception e) {
                e.printStackTrace();
            }

            // ====================================== Messaging =============================================
            
            // STAGE 2.2: Authentication and Session Setup with CLIENT ---------------------------------------
            /*boolean authenticator = hostName.compareTo(messagerToClient.getDestination()) < 0;

            if(authenticator) {
                System.out.println("\n--- INITIATING CLIENT TO CLIENT SESSION SETUP with " + messagerToClient.getDestination() + " ---");
                try {
                    AuthSessiontoClientRequest(out, in);
                } catch(Exception e) {
                    System.out.println ("Unable to authenticate line 169 " + messagerToClient.getDestination());
                }
            } else {
                System.out.println("\n--- waiting for CLIENT TO CLIENT SESSION SETUP from " + messagerToClient.getDestination() + " ---");
            }*/

            /**try {
                AuthSessiontoClient(socket, out, in);
            } catch (Exception e) {
                System.out.println ("Unable to authenticate to " + messagerToClient.getDestination() + "!");
                e.printStackTrace();
            }*/
            
            // STAGE 3: Message Exchange
            System.out.println("You're now chatting with " + messagerToClient.getDestination() + "!");
            System.out.println("(Type '/exit' to leave)");
            System.out.println("------------------------------------------------");
            while(true) {
                // Relay Session Key Expired
                if (!messagerToRelay.isSessionActive()) {
                    messageHandler.interrupt();
                    try { AuthSessiontoRelay(out, in); }
                    catch (Exception e) { e.printStackTrace(); }
                }

                // Client Session Key Expired
                if (clientSessionState != Stages.SESSION || !messagerToClient.isSessionActive()) {
                    clientSessionState = Stages.NO_SESSION;
                    messageHandler.interrupt();
                    try { AuthSessiontoClientRequest(out, in); }
                    catch (Exception e) { e.printStackTrace(); }
                }

                if (messageHandler.isInterrupted() || !messageHandler.isAlive()) {
                    messageHandler.start();
                }


                sendingMessage = scan.nextLine();

                // Check for client disconnect
                if("/exit".equalsIgnoreCase(sendingMessage)){
                    System.out.println("------------------------------------------------");
                    break;
                }

                // Inner message to target client
                String innerMessage = messagerToClient.encodeMessage(
                        Opcode.MESG,
                        sendingMessage
                );

                // Outer message for client to relay
                String outerMessage = messagerToRelay.encodeMessage(
                        Opcode.MESG,
                        hostName,
                        messagerToClient.getDestination(),
                        innerMessage
                );

                // TESTING ...........................
                /*System.out.println("---- INNER ----\n" + 
                                    innerMessage +
                                    "\n---- INNER ----\n");
                System.out.println("---- OUTER ----\n" + 
                                    outerMessage +
                                    "\n---- OUTER ----\n"); */
                // ..................................

                out.println(outerMessage);
            }

            //messageHandler.join(500);
            
        } catch(IOException e) {
            System.out.println(e.getMessage());
        } finally {
            scan.close();
            System.out.println("Client terminated communication");
        }

    }

    /**
     * Has the user choose a target destination for communication with.
     * @param scan 
     * @return MessageManager for User to Target
     */
    private static MessageManager chooseDest(Scanner scan) {
        // Stage 2.15: CHOSING A CLIENT!
        String target;
        PublicKey targetKey = null;
        boolean success = false;

        // Select destination
        do {
            List<String> users = KeyHandler.getAvailableUsers();
            users.remove(hostName);
            
            if (!users.isEmpty()) {
                // Display users
                System.out.println("Who do you want to talk to?");
                for (String user : users) {
                    System.out.println(user);
                }
                // Choose a destination
                System.out.print("Choose (case sensitive): ");
                target = scan.next();
                if (scan.hasNextLine()) { scan.nextLine(); } // Clear buffer

                // Verify chosen user
                try {
                    targetKey = KeyHandler.findPublicKey(target);
                    success = true;
                } catch (Exception e) {
                    System.out.println("Dunno who that is.");
                }
            } 
            // No users found
            else {
                System.out.println("Looks like no one wants to talk to you...");
                System.out.print("Retry (Y/N): ");
                target = scan.next();
                if (scan.hasNextLine()) { scan.nextLine(); } // Clear buffer

                if(target.equalsIgnoreCase("Y")){
                    System.out.println("Retrying...");
                } else {
                    System.out.println("See ya!");
                    return null;
                }
            }
        } while (!success);

        // User to target client 
        return new MessageManager(hostName, kp.getPrivate(), target, targetKey);
    }

    /**
     * STAGE 2.1: Authenticate session setup with relay. 
     * @param socket
     * @param out
     * @param in
     * @throws Exception
     */
    private static void AuthSessiontoRelay (PrintWriter out, BufferedReader in) throws Exception{
        String msgString;
        Message msg;
        HashMap<String, String> list;

        KeyPair dfkeyPair = KeyHandler.createDHKeyPair();
        PublicKey targetDF;
        int challenge1 = KeyHandler.createChallenge();
        int challenge2 = 0;
        SecretKey sessionKey;

        // 1. Client -> Relay: Challenge 1
        list = new HashMap<>();
        list.put("Challenge 1", String.valueOf(challenge1));

        msgString = messagerToRelay.encodeMessage(Opcode.SESR, MessageManager.createListBody(list));
        out.println(msgString);

        // 2. Relay -> Client: Challenge 1 response, Challenge 2, Diffie-Hellman public value
        msgString = in.readLine();
        if (msgString != null) {
            msgString = msgString.trim();
            msg = messagerToRelay.decodeMessage(msgString);

            if (msg.getOpcode() == Opcode.SESR) {
                String body = msg.getBody();
                list = MessageManager.readListBody(body);

                // Verify Challenge 1 response
                if (list.containsKey("Challenge 1 Response")) {
                    int resp = Integer.parseInt(list.get("Challenge 1 Response"));
                    if (challenge1 != resp) {
                        throw new CannotVerifyIntegrity();
                    }
                } else { throw new InvalidMessageFormat("Missing Challenge 1 Response."); }
                
                // Get Challenge 2
                if (list.containsKey("Challenge 2")) {
                    challenge2 = Integer.parseInt(list.get("Challenge 2"));
                } else { throw new InvalidMessageFormat("Missing Challenge 2"); }
                
                // Get D-F public value
                if (list.containsKey("DF Value")) {
                    targetDF = KeyHandler.convertStringtoDFPubKey(list.get("DF Value"));
                } else { throw new InvalidMessageFormat("Missing DF Value"); }
            } 
            else {
                System.out.println("Authentication failed: unexpected Opcode: " + msg.getOpcode());
                throw new InvalidMessageFormat();
            }
        } else { throw new InvalidMessageFormat(); }

        // Derive session key
        sessionKey = KeyHandler.deriveSessionKey(dfkeyPair.getPrivate(), targetDF);
        messagerToRelay.setSession(sessionKey, uid);

        // 3. Client -> Relay: Challenge 2 response, DF Value
        list.clear();
        list.put("Challenge 2 Response", String.valueOf(challenge2));
        list.put("DF Value", KeyHandler.convertDFPubKeytoString(dfkeyPair.getPublic()));

        msgString = messagerToRelay.encodeMessage(Opcode.SESR, MessageManager.createListBody(list));
        out.println(msgString);

        System.out.println("Authenticated and set up session with Relay!");
    }

    /**
     * Stage 2.2 Auth to Client Request
     * @param socket
     * @param out
     * @param in
     * @throws Exception
     */
    private static void AuthSessiontoClientRequest (PrintWriter out, BufferedReader in) throws Exception {
        System.out.println("\n--- CLIENT-TO-CLIENT SESSION SETUP REQUEST with " + messagerToClient.getDestination() + " ---");
        
        String msgString;
        Message outerMsg, innerMsg;
        HashMap<String, String> list = new HashMap<>();;
        
        KeyPair dhKeyPair = KeyHandler.createDHKeyPair();
        int challenge1 = KeyHandler.createChallenge();  
        int challenge2 = 0;                         
        int sessionID = 0;                         

        // 1. SRC -> DST: Challenge 1 -------------------------------------------------------------------------
        System.out.println("1. Sending Challenge 1 to Relay for " + messagerToClient.getDestination() + "...");
        
        msgString = ClientSessionEstablisher.stage1Request(challenge1);
        out.println(msgString);

        //  2. DST -> SRC: Challenge 1 Response, Challenge 2, D-F Public Values --------------------------------
        msgString = in.readLine();
        if (msgString == null) throw new InvalidMessageFormat("No response from Relay after SESC");
        
        // DECODE outer message
        outerMsg = messagerToRelay.decodeMessage(msgString);
        if (outerMsg.getOpcode() != Opcode.SESC) {
            System.out.println("Received unexpected Opcode: " + outerMsg.getOpcode());
            throw new InvalidMessageFormat();
        }
        sessionID = outerMsg.getSessionID();
        messagerToClient.setSessionID(sessionID); 

        // DECODE inner message
        innerMsg = messagerToClient.decodeMessage(outerMsg.getBody());
        if (innerMsg.getOpcode() != Opcode.SESC) throw new InvalidMessageFormat("Inner message is not SESC");
        
        // Parse Message
        challenge2 = ClientSessionEstablisher.stage2Request(innerMsg, challenge1, dhKeyPair, sessionID);

        // 3. SRC -> DST: Challenge 2 Response, DF Value -------------------------------------------------------
        System.out.println("Sending Challenge 2 response and " + hostName + "DH intermediate value...");

        msgString = ClientSessionEstablisher.stage3Request(challenge2, dhKeyPair);
        out.println(msgString);

        System.out.println("Client to Client session key established with " + messagerToClient.getDestination() + " (Session ID: " + sessionID + ").");
    }

    /**
     * Stage 2.2 Auth to Client Response
     * @param socket
     * @param out
     * @param in
     * @param msg Initial Message from DST
     * @throws Exception
     */
    private static void AuthSessiontoClientResponse (PrintWriter out, BufferedReader in, Message msg) throws Exception {
        System.out.println("\n--- CLIENT-TO-CLIENT SESSION SETUP REQUEST with " + messagerToClient.getDestination() + " ---");
        
        String msgString;
        Message outerMsg, innerMsg;
        HashMap<String, String> list = new HashMap<>();;
        
        KeyPair dhKeyPair = KeyHandler.createDHKeyPair();
        int challenge1 = 0;  
        int challenge2 = KeyHandler.createChallenge();                         
        int sessionID = 0;    
        
        // 1. SRC <- DST: Challenge 1 -------------------------------------------------------------------------
        System.out.println("1. Recieved Challenge 1 from " + messagerToClient.getDestination() + "...");
        
        challenge1 = ClientSessionEstablisher.stage1Response(msg);

        //  2. SRC -> DST: Challenge 1 Response, Challenge 2, D-F Public Values --------------------------------
        System.out.println("Sending Challenge 1 response, Challenge 2, and " + hostName + "DH intermediate value...");
        out.println(ClientSessionEstablisher.stage2Response(challenge1, challenge2, dhKeyPair));

        // 3. SRC <- DST: Challenge 2 Response, DF Value -------------------------------------------------------
        msgString = in.readLine();
        if (msgString == null) throw new InvalidMessageFormat("No response from Relay after SESC");
        
        // DECODE outer message
        outerMsg = messagerToRelay.decodeMessage(msgString);
        if (outerMsg.getOpcode() != Opcode.SESC) {
            throw new InvalidMessageFormat("Received unexpected Opcode: " + outerMsg.getOpcode());
        }
        sessionID = outerMsg.getSessionID();
        messagerToClient.setSessionID(sessionID); 

        // DECODE inner message
        innerMsg = messagerToClient.decodeMessage(outerMsg.getBody());
        if (innerMsg.getOpcode() != Opcode.SESC) {
            throw new InvalidMessageFormat("Received unexpected Opcode: " + outerMsg.getOpcode());
        }
        
        // Parse Message
        SecretKey key = ClientSessionEstablisher.stage3Response(innerMsg, challenge2, dhKeyPair);
        messagerToClient.setSession(key, sessionID);

        System.out.println("Client to Client session key established with " + messagerToClient.getDestination() + " (Session ID: " + sessionID + ").");
    }


    private static class MessageHandler extends Thread {
        private BufferedReader serverStream;
        private PrintWriter clientOut;
        private KeyPair dhKeyPair;
        private int challenge2 = 0;
        private int challenge1 = 0;
        private int sessionID;

        public MessageHandler(BufferedReader serverStream, PrintWriter clientOut) {
            this.serverStream = serverStream;
            this.clientOut = clientOut;
        }

        public void run() {
            String serverResponse; 
            try {
                while((serverResponse = serverStream.readLine()) != null) {
                    //Message serverMessage = new Message(serverResponse);
                    Message serverMessage = messagerToRelay.decodeMessage(serverResponse);

                    // Client to Client Message
                    if (serverMessage.getOpcode() == Opcode.MESG) {
                        //Message clientMessage = new Message(serverMessage.getBody());
                        Message clientMessage = messagerToClient.decodeMessage(serverMessage.getBody());
                        System.out.println(clientMessage.getSender() + ": " + clientMessage.getBody());
                    } 

                    // Request to Authenticate Client to Client
                    else if(serverMessage.getOpcode() == Opcode.SESC) {
                        clientSessionState = Stages.NO_SESSION;
                        try {
                            Message innerMsg = messagerToClient.decodeMessage(serverMessage.getBody());
                            if (innerMsg.getOpcode() != Opcode.SESC) {
                                throw new InvalidMessageFormat("Inner message is not SESC.");
                            }
                            AuthSessiontoClientResponse(clientOut, serverStream, innerMsg);
                        } catch (Exception e) {
                            clientSessionState = Stages.NO_SESSION;
                            e.printStackTrace();
                            return;
                        }
                    }
                    
                    // Error: Session Key with Replay Expired/Invalid
                    else if (serverMessage.getOpcode() == Opcode.ERSR) {
                        messagerToRelay.resetSession();
                        // %%%
                    }

                    // Error: Session Key with Recipient Client Expired/Invalid
                    else if (serverMessage.getOpcode() == Opcode.ERSC) {
                        clientSessionState = Stages.NO_SESSION;
                        messagerToClient.resetSession();
                        // %%%
                    }

                    // Error: Message Invalid
                    else if (serverMessage.getOpcode() == Opcode.ERRM) {
                        // %%%
                    }

                    // Error: Recipient Not Found
                    else if (serverMessage.getOpcode() == Opcode.ERNF) {
                        // %%%
                    }
                }
            }
            catch (Exception e) {
                System.out.println("Unable to read message!");
                e.printStackTrace();
            }
        }
    }

    private static class ClientSessionEstablisher
    {
        static private HashMap<String, String> list = new HashMap<>();
        
        /**
         * 1. SRC -> DST (Request): Challenge 1
         * @param challenge1 Challenge 1
         * @return Message
         */
        static private String stage1Request (int challenge1) throws Exception{
            System.out.println("Session Establishment: Stage 1 (Request " + messagerToClient.getDestination() + ")");
            if (clientSessionState != Stages.NO_SESSION) { throw new UnknownSessionEstablishmentState("Session Establishment in Progress!");}
            clientSessionState = Stages.STAGE1_REQUEST;

            System.out.println("1. Sending Challenge 1 to Relay for " + messagerToClient.getDestination() + "...");
            
            list.clear();
            list.put("Challenge 1", String.valueOf(challenge1));

            String innerMsgString = messagerToClient.encodeMessage(
                Opcode.SESC,
                MessageManager.createListBody(list) // Challenge 1
            );

            String outerMsgString = messagerToRelay.encodeMessage(
                Opcode.SESC,  
                hostName,
                messagerToClient.getDestination(),
                innerMsgString
            );

            return outerMsgString;
        }

        /**
         * 1. SRC <- DST (Response): Challenge 1
         * @param msg Message Received
         * @return Challenge 1 
         * @throws Exception
         */
        static private int stage1Response (Message msg) throws Exception{
            System.out.println("Session Establishment: Stage 1 (Response " + messagerToClient.getDestination() + ")");
            if (clientSessionState != Stages.NO_SESSION) { throw new UnknownSessionEstablishmentState("Session Establishment in Progress!");}
            if (msg.getOpcode() != Opcode.SESC) { throw new InvalidMessageFormat("Expecting Client Session Establishment."); }
            clientSessionState = Stages.STAGE1_RESPONSE;

            String body = msg.getBody();
            list = MessageManager.readListBody(body);

            // Verify Challenge 1 response
            if (list.containsKey("Challenge 1")) {
                return Integer.parseInt(list.get("Challenge 1"));
            } else { throw new InvalidMessageFormat("Missing Challenge 1."); }
        }

        /**
         * 2. SRC <- DST (Request): Challenge 1 Response, Challenge 2, D-F Public Values
         * @param challenge1 Challenge 1
         * @param dhKeyPair Source's Diffie-Hellman Key Pair
         * @param sessionID SessionID for this Session
         * @return Challenge 2
         */
        static private int stage2Request (Message msg, int challenge1, KeyPair dhKeyPair, int sessionID) throws Exception{
            System.out.println("Session Establishment: Stage 2 (Request " + messagerToClient.getDestination() + ")");
            if (clientSessionState != Stages.STAGE1_REQUEST) {throw new UnknownSessionEstablishmentState();}
            if (msg.getOpcode() != Opcode.SESC) { throw new InvalidMessageFormat("Expecting Client Session Establishment."); }
            clientSessionState = Stages.STAGE2_REQUEST;

            list = MessageManager.readListBody(msg.getBody());
            String targetInterKey = messagerToClient.getDestination() + " DF Value";

            // Check for Request
            if (list.containsKey("Challenge 1")) {
                clientSessionState = Stages.NO_SESSION;
                throw new UnknownSessionEstablishmentState("New Session Establishment Request!");
            }

            // Get Challenge 1 Response
            if (!list.containsKey("Challenge 1 Response")) { throw new InvalidMessageFormat("Missing Challenge 1 Response."); }
            int challenge1Resp = Integer.parseInt(list.get("Challenge 1 Response"));

            // Verify Challenge 1 Response
            if (challenge1 != challenge1Resp) {
                System.out.println("Challenge 1 verification failed. Restarting.");
                throw new CannotVerifyIntegrity("Challenge 1 Response mismatch. Authentication failed.");
            }

            // Get Challenge 2
            if (!list.containsKey("Challenge 2")) throw new InvalidMessageFormat("Missing Challenge 2.");
            int challenge2 = Integer.parseInt(list.get("Challenge 2"));

            // Get D-F Public Value
            if (!list.containsKey(targetInterKey)){
                throw new InvalidMessageFormat("Missing " + messagerToClient.getDestination() + "'s intermediate DF value");
            }
            PublicKey targetDF = KeyHandler.convertStringtoDFPubKey(list.get(targetInterKey));

            // Derive session key
            SecretKey key = KeyHandler.deriveSessionKey(dhKeyPair.getPrivate(), targetDF);
            messagerToClient.setSession(key, sessionID);

            return challenge2;
        }

        /**
         * 2. SRC -> DST (Response): Challenge 1 response, Challenge 2, Diffie-Hellman public value
         * @param challenge1 Challenge 1
         * @param challenge2 Challenge 2
         * @param dhKeyPair Diffie-Hellman Key Pair
         * @return Message
         * @throws Exception
         */
        static private String stage2Response (int challenge1, int challenge2, KeyPair dhKeyPair) throws Exception{
            System.out.println("Session Establishment: Stage 2 (Response " + messagerToClient.getDestination() + ")");
            if (clientSessionState != Stages.STAGE1_RESPONSE) { throw new UnknownSessionEstablishmentState(); }
            clientSessionState = Stages.STAGE2_RESPONSE;

            list.clear();
            list.put("Challenge 1 Response", String.valueOf(challenge1));
            list.put("Challenge 2", String.valueOf(challenge2));
            list.put(hostName + " DF Value", KeyHandler.convertDFPubKeytoString(dhKeyPair.getPublic()));

            String innerMsgString = messagerToClient.encodeMessage(
                Opcode.SESC,
                MessageManager.createListBody(list) // Challenge 1
            );

            return messagerToRelay.encodeMessage(
                Opcode.SESC,  
                hostName,
                messagerToClient.getDestination(),
                innerMsgString
            );
        }

        /**
         * 3. SRC -> DST (Request): Challenge 2 Response, DF Value
         * @param challenge2 Challenge 2 Response
         * @param dhKeyPair Diffie-Hellman Key Pair
         * @return Message
         * @throws Exception
         */
        static private String stage3Request (int challenge2, KeyPair dhKeyPair) throws Exception{
            System.out.println("Session Establishment: Stage 3 (Request " + messagerToClient.getDestination() + ")");
            if (clientSessionState != Stages.STAGE2_REQUEST) { throw new UnknownSessionEstablishmentState(); }
            clientSessionState = Stages.SESSION;

            list.clear();
            list.put("Challenge 2 Response", String.valueOf(challenge2));
            list.put(hostName + " DF Value", KeyHandler.convertDFPubKeytoString(dhKeyPair.getPublic()));

            String innerMsgString = messagerToClient.encodeMessage(
                Opcode.SESC,
                MessageManager.createListBody(list)
            );

            System.out.println("Session Established with " + messagerToClient.getDestination() + "!");

           return messagerToRelay.encodeMessage(
                Opcode.SESC,  
                hostName,
                messagerToClient.getDestination(),
                innerMsgString
            );
        }

        /**
         * 3. SRC <- DST (Response): Challenge 2 response, DF Value
         * @param msg Message
         * @param challenge2 Challenge 2 Response
         * @param dhKeyPair Diffie-Hellman Key Pair
         * @return Session Key
         * @throws Exception
         */
        static private SecretKey stage3Response (Message msg, int challenge2, KeyPair dhKeyPair) throws Exception {
            System.out.println("Session Establishment: Stage 3 (Response " + messagerToClient.getDestination() + ")");
            if (clientSessionState != Stages.STAGE2_RESPONSE) { throw new UnknownSessionEstablishmentState(); }
            if (msg.getOpcode() != Opcode.SESC) { throw new InvalidMessageFormat("Expecting Client Session Establishment."); }
            
            list = MessageManager.readListBody(msg.getBody());
            String targetInterKey = messagerToClient.getDestination() + " DF Value";

            // Check for Request
            if (list.containsKey("Challenge 1")) {
                clientSessionState = Stages.NO_SESSION;
                throw new UnknownSessionEstablishmentState("New Session Establishment Request!");
            }

            // Verify Challenge 2 response
            if (list.containsKey("Challenge 2 Response")) {
                int resp = Integer.parseInt(list.get("Challenge 2 Response"));
                if (challenge2 != resp) { throw new CannotVerifyIntegrity("Challenge 2 invalid."); }
            } else { throw new InvalidMessageFormat(); }

            // Get D-F public value
            if (list.containsKey(targetInterKey)) {
                PublicKey targetDF = KeyHandler.convertStringtoDFPubKey(list.get(targetInterKey));
                clientSessionState = Stages.SESSION;
                System.out.println("Session Established with " + messagerToClient.getDestination() + "!");
                return KeyHandler.deriveSessionKey(dhKeyPair.getPrivate(), targetDF);
            } else { throw new InvalidMessageFormat(); }
        }


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
