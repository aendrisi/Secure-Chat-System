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
    private static final String RELAY_NAME = "Relay";
    private static final String serverHost = "localhost";
    private static final int serverPort = 1025; 

    private static MessageManager messagerToRelay;
    private static MessageManager messagerToClient;

    private static String hostName;
    private static int uid;

    private static String sessionID;

    private static PrintWriter serverOut;

    private static KeyPair kp;


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
            //messageHandler.start(); 

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

            // create registration message 
            sendingMessage = messagerToRelay.encodeMessage(
                Opcode.REGI,
                encodedPublicKey
            );

            out.println(sendingMessage); // Client -> Relay: Registration with public key
            receivingMessage = in.readLine(); // Relay -> Client: Registration UID

            // Parse message for UID
            if(receivingMessage != null) {
                String trimmedResponse = receivingMessage.trim();
                try {
                    Message uidResponse = messagerToRelay.decodeMessage(trimmedResponse);
                    if (uidResponse.getOpcode() == Opcode.REGI) {
                        String uidBody = uidResponse.getBody().trim();

                        //get the UID
                        uid = Integer.parseInt(uidBody);
                        System.out.println(uidResponse);
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
                AuthSessiontoRelay(socket, out, in);
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
            
            // STAGE 2.2: Authentication and Session Setup with CLIENT ---------------------------------------
            try {
                AuthSessiontoClient(socket, out, in);
            } catch (Exception e) {
                System.out.println ("Unable to authenticate to " + messagerToClient.getDestination() + "!");
                e.printStackTrace();
            }
            
            // STAGE 3: Message Exchange
            messageHandler.start();
            System.out.println("You're now chatting with " + messagerToClient.getDestination() + "!");
            System.out.println("(Type '/exit' to leave)");
            System.out.println("------------------------------------------------");
            while(true) {
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
    private static void AuthSessiontoRelay (Socket socket, PrintWriter out, BufferedReader in) throws Exception{
        if (socket.isConnected()) {
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
                    } else { throw new InvalidMessageFormat(); }
                    // Get Challenge 2
                    if (list.containsKey("Challenge 2")) {
                        challenge2 = Integer.parseInt(list.get("Challenge 2"));
                    } else { throw new InvalidMessageFormat(); }
                    // Get D-F public value
                    if (list.containsKey("DF Value")) {
                        targetDF = KeyHandler.convertStringtoDFPubKey(list.get("DF Value"));
                    } else { throw new InvalidMessageFormat(); }
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
            list = new HashMap<>();
            list.put("Challenge 2 Response", String.valueOf(challenge2));
            list.put("DF Value", KeyHandler.convertDFPubKeytoString(dfkeyPair.getPublic()));

            msgString = messagerToRelay.encodeMessage(Opcode.SESR, MessageManager.createListBody(list));
            out.println(msgString);

            System.out.println("Authenticated and set up session with Relay!");
            }

    }

    //Stage 2.2 Auth to Client
    private static void AuthSessiontoClient (Socket socket, PrintWriter out, BufferedReader in) throws Exception {
        if (!socket.isConnected()) {
            throw new IOException("Socket is not connected to the Relay.");
        }
        
        System.out.println("\n--- CLIENT-TO-CLIENT SESSION SETUP with " + messagerToClient.getDestination() + " ---");
        
        String msgString;
        Message outerMsg, innerMsg;
        HashMap<String, String> list;
        
        KeyPair dhKeyPair = null;
        PublicKey targetDF;
        SecretKey sessionKey;
        int challenge1 = KeyHandler.createChallenge();  
        int challenge2 = 0;                         
        int sessionID = 0;                         

        System.out.println("1. Sending Challenge 1 to Relay for " + messagerToClient.getDestination() + "...");
        
        list = new HashMap<>();
        list.put("Challenge 1", String.valueOf(challenge1));
        String innerBody = MessageManager.createListBody(list);
        
        String innerMessage = messagerToClient.encodeMessage(Opcode.SESC, innerBody);

        String outerMessage = messagerToRelay.encodeMessage(
            Opcode.SESC,  
            hostName,
            messagerToClient.getDestination(),
            innerMessage
        );
        out.println(outerMessage);

        msgString = in.readLine();
        if (msgString == null) throw new InvalidMessageFormat("No response from Relay after SESC");
        
        outerMsg = messagerToRelay.decodeMessage(msgString);
        if (outerMsg.getOpcode() != Opcode.SESC) {
            System.out.println("Received unexpected Opcode: " + outerMsg.getOpcode());
            throw new InvalidMessageFormat();
        }
        sessionID = outerMsg.getSessionID();
        messagerToClient.setSessionID(sessionID); 

        innerMsg = messagerToClient.decodeMessage(outerMsg.getBody());
        
        if (innerMsg.getOpcode() != Opcode.SESC) throw new InvalidMessageFormat("Inner message is not SESC");
        
        list = MessageManager.readListBody(innerMsg.getBody());

        if (!list.containsKey("Challenge 1 Response")) throw new InvalidMessageFormat("Missing Challenge 1 Response.");
        int challenge1Resp = Integer.parseInt(list.get("Challenge 1 Response"));
        if (challenge1 != challenge1Resp) {
            System.out.println("Challenge 1 verification failed. Restarting.");
            throw new CannotVerifyIntegrity("Challenge 1 Response mismatch. Authentication failed.");
        }
        System.out.println("4. Challenge 1 verified. Received Bob's DH parameters and Challenge 2.");

        if (!list.containsKey("Challenge 2")) throw new InvalidMessageFormat("Missing Challenge 2.");
        challenge2 = Integer.parseInt(list.get("Challenge 2"));

        if (!list.containsKey("Bob intermediate value")) throw new InvalidMessageFormat("Missing Bob's intermediate DF value.");
        String bobDFValue = list.get("Bob intermediate value");

        dhKeyPair = KeyHandler.createDHKeyPair(list.get("global parameters")); 
        targetDF = KeyHandler.convertStringtoDFPubKey(bobDFValue);

        sessionKey = KeyHandler.deriveSessionKey(dhKeyPair.getPrivate(), targetDF);
        messagerToClient.setSession(sessionKey, sessionID);

        System.out.println("5. Sending Challenge 2 response and Alice's DH intermediate value...");

        list = new HashMap<>();
        list.put("Challenge 2 Response", String.valueOf(challenge2));
        list.put("Alice intermediate value", KeyHandler.convertDFPubKeytoString(dhKeyPair.getPublic()));

        innerBody = MessageManager.createListBody(list);
        
        String innerMessageFinal = messagerToClient.encodeMessage(Opcode.SESC, innerBody);

        outerMessage = messagerToRelay.encodeMessage(
            Opcode.SESC,  
            hostName,
            messagerToClient.getDestination(),
            innerMessageFinal
        );
        out.println(outerMessage);

        System.out.println("Client-to-Client session key established with " + messagerToClient.getDestination() + " (Session ID: " + sessionID + ").");

    }

    private static class MessageHandler extends Thread {
        private BufferedReader serverStream;
        private PrintWriter clientOut;
        private KeyPair dhKeyPair;
        private int challenge2;

        public MessageHandler(BufferedReader serverStream, PrintWriter clientOut) {
            this.serverStream = serverStream;
            this.clientOut = clientOut;
        }

        public void run() {
            try {
                String serverResponse; 
                while((serverResponse = serverStream.readLine()) != null) {
                    try {
                        //Message serverMessage = new Message(serverResponse);
                        Message serverMessage = messagerToRelay.decodeMessage(serverResponse);

                        // Client to Client Message
                        if (serverMessage.getOpcode() == Opcode.MESG) {
                            //Message clientMessage = new Message(serverMessage.getBody());
                            Message clientMessage = messagerToClient.decodeMessage(serverMessage.getBody());
                            System.out.println(clientMessage.getSender() + ": " + clientMessage.getBody());
                        } else if(serverMessage.getOpcode() == Opcode.SESC) {
                            Message innerMsg = messagerToClient.decodeMessage(serverMessage.getBody());
                            
                            if (innerMsg.getOpcode() != Opcode.SESC) {
                                throw new InvalidMessageFormat("Inner message is not SESC.");
                            }

                            HashMap<String, String> list = MessageManager.readListBody(innerMsg.getBody());
                                if (list.containsKey("Challenge 1")) {
                                    if (dhKeyPair != null) {
                                        System.err.println("Warning: Received new SESC request before completing previous session setup.");
                                        dhKeyPair = null;
                                        challenge2 = 0;
                                    }
                                int challenge1 = Integer.parseInt(list.get("Challenge 1"));
                                System.out.println("2. Received Challenge 1 (" + challenge1 + ") from " + innerMsg.getSender() + ".");

                                this.dhKeyPair = KeyHandler.createDHKeyPair();
                                this.challenge2 = KeyHandler.createChallenge();

                                list = new HashMap<>();
                                list.put("Challenge 1 Response", String.valueOf(challenge1));
                                list.put("Challenge 2", String.valueOf(challenge2));
                                list.put("global parameters", KeyHandler.convertDFPubKeytoString(dhKeyPair.getPublic())); 
                                list.put("Bob intermediate value", KeyHandler.convertDFPubKeytoString(dhKeyPair.getPublic()));

                                String innerBody = MessageManager.createListBody(list);
                                String innerMessageFinal = messagerToClient.encodeMessage(Opcode.SESC, innerBody);

                                String outerMessage = messagerToRelay.encodeMessage(
                                    Opcode.SESC, 
                                    innerMsg.getReceiver(),  
                                    innerMsg.getSender(),    
                                    innerMessageFinal
                                );

                                clientOut.println(outerMessage);
                                System.out.println("Sent Challenge 1 Response, Challenge 2 (" + challenge2 + ") and DH parameters back to " + innerMsg.getSender() + ".");
                            } else if(list.containsKey("Challenge 2 response")) {
                                System.out.println("Received final DH value from " + innerMsg.getSender() + ".");
                                if (dhKeyPair == null || challenge2 == 0) {
                                    System.err.println("ERROR: Missing ephemeral DH state for key derivation in Step 3.");
                                    throw new InvalidMessageFormat("State error: Cannot verify Challenge 2.");
                                }
                                int receivedChallenge2Resp = Integer.parseInt(list.get("Challenge 2 Response"));
                                
                                if (receivedChallenge2Resp != challenge2) {
                                    dhKeyPair = null;
                                    challenge2 = 0;
                                    throw new CannotVerifyIntegrity("Challenge 2 response mismatch. Authentication failed.");
                                }

                                if (!list.containsKey("Alice intermediate value")) {
                                    throw new InvalidMessageFormat("Missing Alice's intermediate DF value.");
                                }

                                PublicKey aliceDF = KeyHandler.convertStringtoDFPubKey(list.get("Alice intermediate value"));
                                SecretKey finalSessionKey = KeyHandler.deriveSessionKey(dhKeyPair.getPrivate(), aliceDF);
                                messagerToClient.setSession(finalSessionKey, serverMessage.getSessionID());
                                dhKeyPair = null;  
                                challenge2 = 0;
                                System.out.println("Client-to-Client session key established with " + innerMsg.getSender() + " (Session ID: " + serverMessage.getSessionID() + ").");

                            } else {
                                throw new InvalidMessageFormat("SESC message is missing required challenge fields.");   
                            }


                        }
                    }
                    catch (Exception e) {
                        System.out.println("Unable to read message!");
                        e.printStackTrace();
                    }
                }
            } catch(IOException e) {
                System.out.println("Server closed");
                e.printStackTrace();
            }
        }


    }

}
