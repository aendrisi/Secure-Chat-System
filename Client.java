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
import java.time.format.DateTimeFormatter;
import java.util.Base64;
import java.util.List;
import java.util.HashMap;

public class Client {
    private static final String RELAY_NAME = "Relay";
    private static final String serverHost = "localhost";
    private static final int serverPort = 1025; 
    private static final int SLEEP_DURATION = 500;

    private static MessageManager messagerToRelay;
    private static SessionSetup relaySeshSetup = new SessionSetup();
    private static MessageManager messagerToClient;
    private static SessionSetup clientSeshSetup = new SessionSetup();

    private static String hostName;
    private static int uid;

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
            HashMap<String, String> list = new HashMap<>();; 

            // MessageManager for User to Relay communication
            try {
                messagerToRelay = new MessageManager(hostName, kp.getPrivate(), RELAY_NAME);
            } catch (Exception e) {
                System.out.println("Error: Unable to locate Relay server's public key! " + e);
                scan.close();
                KeyHandler.deletePublicKey(hostName);
                return;
            }
            
            try {
                PublicKey relayPubKey = KeyHandler.findPublicKey(RELAY_NAME);
                messagerToRelay.setDestPubKey(relayPubKey);
                System.out.println("Relay public key preloaded successfully");
            } catch(Exception e) {
                System.out.println("Couldnt preload relay public key");
                scan.close();
                KeyHandler.deletePublicKey(hostName);
                return;
            }

            // STAGE 1: Registration -----------------------------------------------------------------
            System.out.println("Registering with Relay.");
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
                    PublicKey relayPubKey = KeyHandler.findPublicKey(RELAY_NAME);
                    messagerToRelay.setDestPubKey(relayPubKey);
                } catch(Exception e) {
                    System.out.println("Failed to load relay public key: " + e.getMessage());
                    return;
                }

                try {
                    Message uidResponse = messagerToRelay.decodeMessage(trimmedResponse);
                    if (uidResponse.getOpcode() == Opcode.REGI) {
                        String uidBody = uidResponse.getBody();
                        list = MessageManager.readListBody(uidBody);

                        // Get UID
                        if (list.containsKey("UID")) {
                            uid = Integer.parseInt(list.get("UID"));
                        } //else { throw new InvalidMessageFormat(); }

                        System.out.println("Registration successful. UID: " + uid);
                        
                    } else {
                        System.out.println("Registration failed: unexpected Opcode: " + uidResponse.getOpcode());
                        scan.close();
                        KeyHandler.deletePublicKey(hostName);
                        return;
                    }
                } 
                catch (NumberFormatException e) {
                    System.out.println("Registration failed: invalid UID format");
                    scan.close();
                    KeyHandler.deletePublicKey(hostName);
                    return;
                }
                catch (Exception e) {
                    System.out.println("Registration failed: Failed to decode response");
                    e.printStackTrace();
                    System.out.println(e.getMessage());
                    scan.close();
                    KeyHandler.deletePublicKey(hostName);
                    return;
                }      
            } else {
                System.out.println("Registration failed: null response");
                scan.close();
                KeyHandler.deletePublicKey(hostName);
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
                String msgStr;
                Message msg;

                // 1. Client -> Relay: Challenge 1
                msgStr = relaySeshSetup.requestSession();
                out.println(messagerToRelay.encodeMessage(Opcode.SESR, msgStr));

                // 2. Relay -> Client: Challenge 1 Response, Challenge 2, DF Value
                msgStr = in.readLine();
                msg = messagerToRelay.decodeMessage(msgStr);
                if (msg.getOpcode() != Opcode.SESR) { throw new InvalidMessageFormat(); }

                // 3. Client -> Relay: Challenge 2 Response, DF Value
                msgStr = relaySeshSetup.nextStep(MessageManager.readListBody(msg.getBody()));
                out.println(messagerToRelay.encodeMessage(Opcode.SESR, msgStr));
                
                // Derive Key
                if (relaySeshSetup.getKey() != null) {
                    System.out.println("> Relay-Client Key: " + 
                        Base64.getEncoder().encodeToString(relaySeshSetup.getKey().getEncoded()));
                    messagerToRelay.setSession(relaySeshSetup.getKey(), uid);
                }
            } catch (Exception e) {
                System.out.println ("Error: Unable to authenticate to relay!");
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

            // Stage 2.5: Session Establishment with Client ----------------------------------------
            try {
                if (in.ready()) {
                    // 1. SRC <- DST: Challenge 1
                    String msgString = in.readLine().trim();
                    Message outerMsg = messagerToClient.decodeMessage(msgString);
                    if (outerMsg.getOpcode() != Opcode.SESC) { throw new InvalidMessageFormat(); }
                    Message innerMsg = messagerToClient.decodeMessage(outerMsg.getBody());
                    if (innerMsg.getOpcode() != Opcode.SESC) { throw new InvalidMessageFormat(); }
                    
                    // 2. SRC -> DST: Challenge 1 Response, Challenge 2, D-F Public Values
                    msgString = clientSeshSetup.nextStep(MessageManager.readListBody(innerMsg.getBody())); 
                    out.println(
                        messagerToRelay.encodeMessage(
                            Opcode.SESC, 
                            messagerToClient.getSource(),
                            messagerToClient.getDestination(),
                            messagerToClient.encodeMessage(Opcode.SESC, msgString)
                        )
                    );

                    // 3. SRC <- DST: Challenge 2 response, DF Value
                    msgString = in.readLine().trim();
                    outerMsg = messagerToClient.decodeMessage(msgString);
                    if (outerMsg.getOpcode() != Opcode.SESC) { throw new InvalidMessageFormat(); }
                    innerMsg = messagerToClient.decodeMessage(outerMsg.getBody());
                    if (innerMsg.getOpcode() != Opcode.SESC) { throw new InvalidMessageFormat(); }

                    clientSeshSetup.nextStep(MessageManager.readListBody(innerMsg.getBody()));
                     
                } else {
                    String msgStr;

                    // 1. SRC -> DST: Challenge 1
                    msgStr = clientSeshSetup.requestSession();
                    out.println(
                        messagerToRelay.encodeMessage(
                            Opcode.SESC, 
                            messagerToClient.getSource(),
                            messagerToClient.getDestination(),
                            messagerToClient.encodeMessage(Opcode.SESC, msgStr)
                        )
                    );

                    // 2. DST -> SRC: Challenge 1 Response, Challenge 2, DF Value
                    msgStr = in.readLine();
                    Message outerMsg = messagerToClient.decodeMessage(msgStr);
                    if (outerMsg.getOpcode() != Opcode.SESC) { throw new InvalidMessageFormat(); }
                    Message innerMsg = messagerToClient.decodeMessage(outerMsg.getBody());
                    if (innerMsg.getOpcode() != Opcode.SESC) { throw new InvalidMessageFormat(); }
  

                    // 3. SRC -> DST: Challenge 2 Response, DF Value
                    msgStr = clientSeshSetup.nextStep(MessageManager.readListBody(innerMsg.getBody()));
                    out.println(
                        messagerToRelay.encodeMessage(
                            Opcode.SESC, 
                            messagerToClient.getSource(),
                            messagerToClient.getDestination(),
                            messagerToClient.encodeMessage(Opcode.SESC, msgStr)
                        )
                    );

                }

                // Derive Key
                if (clientSeshSetup.getKey() != null) {
                    System.out.println("> Client-Client Key: " + Base64.getEncoder().encodeToString(clientSeshSetup.getKey().getEncoded()));
                    messagerToClient.setSession(clientSeshSetup.getKey(), uid);
                } else { throw new UnknownSessionEstablishmentState("Session not set up!"); }

            } catch(UnknownSessionEstablishmentState | CannotVerifyIntegrity | InvalidMessageFormat e) {
                //System.out.println("Attempting to reestablish client session");
                e.printStackTrace();
                System.out.println("Error: Unable to establish session with " + messageHandler.getName());
            } catch (Exception e) {
                e.printStackTrace();
            }

            // ====================================== Messaging =============================================
            
            // STAGE 3: Message Exchange
            System.out.println(); System.out.println();
            System.out.println("You're now chatting with " + messagerToClient.getDestination() + "!");
            System.out.println("(Type '/exit' to leave)");
            System.out.println("------------------------------------------------");
            boolean chatActive = true;

            while(chatActive) {
                // Relay Session Key Expired --> Request new one
                if (!messagerToRelay.isSessionActive()) {
                    // Request new session with relay
                    if (relaySeshSetup.getState() != SessionSetup.State.PROCESSING) {
                        System.out.println("Session: Connection with Relay has been lost!");
                        relaySeshSetup.resetSession();

                        // Send Request for new session key
                        sendingMessage = relaySeshSetup.requestSession();
                        out.println(messagerToRelay.encodeMessage(Opcode.SESR, sendingMessage));
                        System.out.println("------------------------------------------------");
                    }
                    else { Thread.sleep(SLEEP_DURATION); }
                    
                }
                // Client Session Key Expired --> Request new one
                else if (!messagerToClient.isSessionActive()) {
                    // Request new session with client
                    if (clientSeshSetup.getState() != SessionSetup.State.PROCESSING) {
                        System.out.println("Session: Connection with " + messagerToClient.getDestination() + " has been lost!");
                        clientSeshSetup.resetSession();

                        // Send Request for new session key
                        sendingMessage = clientSeshSetup.requestSession();
                        out.println(
                            messagerToRelay.encodeMessage(
                                Opcode.SESC, 
                                messagerToClient.getSource(),
                                messagerToClient.getDestination(),
                                messagerToClient.encodeMessage(Opcode.SESC, sendingMessage)
                            )
                        );
                        System.out.println("------------------------------------------------");
                    }
                    else { Thread.sleep(SLEEP_DURATION); }
                }
                // Both sessions are established:
                else {
                    // Enable message handler
                    if (messageHandler.isInterrupted() || !messageHandler.isAlive()) {
                        messageHandler = new MessageHandler(in, out);
                        messageHandler.start();
                    }

                    // Get user input
                    sendingMessage = scan.nextLine();

                    // Command
                    if (sendingMessage.charAt(0) == '/') {
                        // Exit command (client disconnect)
                        if("/exit".equalsIgnoreCase(sendingMessage)){
                            chatActive = false;
                        } 
                        // Help command
                        else if ("/help".equalsIgnoreCase(sendingMessage)) {
                            System.out.println("------------------------------------------------");
                            System.out.println("/help - Shows all commands");
                            System.out.println("/exit - Closes the chat");
                            System.out.println("/expire relay - Expire session with the relay");
                            System.out.println("/expire client - Expire session with the client");
                        }   
                        // Expire Relay
                        else if("/expire relay".equalsIgnoreCase(sendingMessage)){
                            messagerToRelay.resetSession();
                        } 
                        // Expire Client
                        else if("/expire client".equalsIgnoreCase(sendingMessage)){
                            messagerToClient.resetSession();
                        } 
                        else {
                            System.out.println("Unknown command. Try '/help' ?");
                        }
                    }
                    // Send to Client
                    else {
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

                        out.println(outerMessage);
                    }

                    System.out.println("------------------------------------------------");

                }
            }

            // Close everything
            System.out.println("Goodbye!");
            messageHandler.interrupt();
            socket.close();
            in.close();
            out.close();
            
        } catch(IOException e) {
            System.out.println(e.getMessage());
            e.printStackTrace();
        } catch (Exception e) {
            e.printStackTrace();
        } finally {
            scan.close();
            KeyHandler.deletePublicKey(hostName);
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
                System.out.println("--------------- Available Clients --------------");
                for (String user : users) {
                    System.out.println("> " + user);
                }
                System.out.println("------------------------------------------------");   
                System.out.println("Choose a client (case sensitive).");            
                System.out.print("> ");
                target = scan.next();
                if (scan.hasNextLine()) { scan.nextLine(); } // Clear buffer

                // Verify chosen user
                try {
                    targetKey = KeyHandler.findPublicKey(target);
                    success = true;
                } catch (Exception e) {
                    System.out.println(target + " not found.");
                }
            } 
            // No users found
            else {
                System.out.println("--------------- Available Clients --------------");
                System.out.println("[No clients available.]");
                System.out.println("------------------------------------------------");
                System.out.print("Retry (Y/N): ");
                target = scan.next();
                if (scan.hasNextLine()) { scan.nextLine(); } // Clear buffer

                if(!target.equalsIgnoreCase("Y")){
                    System.out.println("No client selected.");
                    System.out.println("------------------------------------------------");
                    return null;
                }
            }
        } while (!success);

        System.out.println("------------------------------------------------");

        // User to target client 
        return new MessageManager(hostName, kp.getPrivate(), target, targetKey);
    }

    private static class MessageHandler extends Thread {
        private BufferedReader serverStream;
        private PrintWriter clientOut;

        private DateTimeFormatter timeFormat = DateTimeFormatter.ofPattern("MM/dd/yyyy HH:mm");

        public MessageHandler(BufferedReader serverStream, PrintWriter clientOut) {
            this.serverStream = serverStream;
            this.clientOut = clientOut;
        }

        /**
         * Listens for messages to the Client
         */
        public void run() {
            String serverResponse; 
            try {
                while((serverResponse = serverStream.readLine()) != null && !Thread.currentThread().isInterrupted()) {
                    //Message serverMessage = new Message(serverResponse);
                    Message serverMessage = messagerToRelay.decodeMessage(serverResponse);

                    // Client to Client Message
                    if (serverMessage.getOpcode() == Opcode.MESG) {
                        Message clientMessage = messagerToClient.decodeMessage(serverMessage.getBody());
                        System.out.println(clientMessage.getSender() + " (" + clientMessage.getTimestamp().format(timeFormat) + "): " + clientMessage.getBody());
                    } 

                    // Session Establishment Client-Relay
                    else if(serverMessage.getOpcode() == Opcode.SESR) {
                        if (relaySeshSetup.getState() == SessionSetup.State.PROCESSING) {
                            // 2. Relay -> Client: Challenge 1 Response, Challenge 2, DF Value
                            String msgStr = relaySeshSetup.nextStep(MessageManager.readListBody(serverMessage.getBody()));
                            
                            // 3. Client -> Relay: Challenge 2 Response, DF Value
                            clientOut.println(messagerToRelay.encodeMessage(Opcode.SESR, msgStr));
                            
                            // Derive Key
                            if (relaySeshSetup.getKey() != null) {
                                System.out.println("> Relay-Client Key: " + 
                                    Base64.getEncoder().encodeToString(relaySeshSetup.getKey().getEncoded()));
                                messagerToRelay.setSession(relaySeshSetup.getKey(), uid);
                            }
                        } else { throw new InvalidMessageFormat("Session setup with relay not requested!"); }
                    }

                    // Session Establishment Client-Client
                    else if(serverMessage.getOpcode() == Opcode.SESC) {
                        Message innerMsg = messagerToClient.decodeMessage(serverMessage.getBody());
                        if (innerMsg.getOpcode() != Opcode.SESC) { throw new InvalidMessageFormat("Opcode mismatch"); }

                        // Steps 1 and 2
                        if (clientSeshSetup.getState() != SessionSetup.State.PROCESSING) {
                            // RESPONSE - 1. SRC <- DST: Challenge 1
                            // REQUEST  - 2. DST -> SRC: Challenge 1 Response, Challenge 2, DF Value
                            String msgString = clientSeshSetup.nextStep(MessageManager.readListBody(innerMsg.getBody())); 

                            // RESPONSE - 2. SRC -> DST: Challenge 1 Response, Challenge 2, D-F Public Values
                            // REQUEST -  3. SRC -> DST: Challenge 2 Response, DF Value
                            clientOut.println(
                                messagerToRelay.encodeMessage(
                                    Opcode.SESC, 
                                    messagerToClient.getSource(),
                                    messagerToClient.getDestination(),
                                    messagerToClient.encodeMessage(Opcode.SESC, msgString)
                                )
                            );
                        }
                        // Step 3
                        else {
                            // RESPONSE - 3. SRC <- DST: Challenge 2 response, DF Value
                            String msgString = clientSeshSetup.nextStep(MessageManager.readListBody(innerMsg.getBody()));
                        
                            if (msgString.length() > 0) {
                                clientOut.println(
                                    messagerToRelay.encodeMessage(
                                        Opcode.SESC, 
                                        messagerToClient.getSource(),
                                        messagerToClient.getDestination(),
                                        messagerToClient.encodeMessage(Opcode.SESC, msgString)
                                    )
                                );
                            }
                        }

                        if (clientSeshSetup.getState() == SessionSetup.State.SESSION) {
                            // Derive Key
                                if (clientSeshSetup.getKey() != null) {
                                    System.out.println("> Client-Client Key: " + Base64.getEncoder().encodeToString(clientSeshSetup.getKey().getEncoded()));
                                    messagerToClient.setSession(clientSeshSetup.getKey(), uid);
                                } else { throw new UnknownSessionEstablishmentState("Session not set up!"); }
                        }
                    }
                    
                    // Error: Session Key with Relay Expired/Invalid
                    else if (serverMessage.getOpcode() == Opcode.ERSR) {
                        messagerToRelay.resetSession();
                        relaySeshSetup.resetSession();
                        System.out.println("> Session key with relay expired/invalid");
                    }

                    // Error: Session Key with Recipient Client Expired/Invalid
                    else if (serverMessage.getOpcode() == Opcode.ERSC) {
                        messagerToClient.resetSession();
                        clientSeshSetup.resetSession();
                        System.out.println("> Session key with client expired/invalid");
                    }

                    // Error: Message Invalid
                    else if (serverMessage.getOpcode() == Opcode.ERRM) {
                        System.out.println("> Message invalid");
                        try {
                            System.out.println(serverMessage.getBody());
                        } catch(Exception ignore) {
                            //ignore the invalid message?
                        }
                    }

                    // Error: Recipient Not Found
                    else if (serverMessage.getOpcode() == Opcode.ERNF) {
                        System.out.println("> " + messagerToClient.getDestination() + " is not found");
                    }
                    System.out.println("------------------------------------------------");
                }
            } catch(InterruptedException e) {
                System.out.println("Message Handler interrupted");
            } catch (SocketException e) {
                System.out.println("Closing connection.");
            } catch (Exception e) {
                System.out.println("Unable to read message!");
                e.printStackTrace();
            }
        }
    }
}
