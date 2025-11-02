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
    private static SecretKey sessionKey;

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
            MessageHandler messageHandler = new MessageHandler(in);
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
            
            // STAGE 1: Registration
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


            // Authenticate, session setup, and messaging
            // STAGE 2.1: Authentication and Session Setup with RELAY
            try {
                AuthSessiontoRelay(socket, out, in);
            } catch (Exception e) {
                System.out.println ("Unable to authenticate to relay! ");
                e.printStackTrace();
            }
            

            // ...
            //System.out.println("Skipping STAGE 2.1");
            // Stage 2.15: CHOSING A CLIENT!

            messagerToClient = chooseDest(scan);
            // verify destination was chosen
            if (messagerToClient == null) {
                scan.close();
                KeyHandler.deletePublicKey(hostName);
                return;
            }
            
            // STAGE 2.2: Authentication and Session Setup with CLIENT
            //%%% INCOMPLETE %%%//
            // ...
            try {
                // 1. Generate diffie-hellman key pairs
                KeyPair userDKP = KeyHandler.createDHKeyPair();
                KeyPair targetDKP = KeyHandler.createDHKeyPair(); // TEST: should be replaced with the public key from the target

                // 2. Share user's Diffie-Hellman public key to target

                // 3. Get target's Diffie-Hellman public key
                PublicKey targetDFKey = targetDKP.getPublic(); // TEST: should be replaced
                
                // 4. Derive shared secret  
                sessionKey = KeyHandler.deriveSessionKey(userDKP.getPrivate(), targetDFKey);

                //uid = 5; // TEST: should be given by the Relay
                sessionID = "TEMP_SESSIONID"; // TEST: shoule be given by Relay

                messagerToClient.setSession(sessionKey, sessionID);
            } catch (Exception e) {} 
            
            messageHandler.start();
            // STAGE 3: Message Exchange
            while(true) {
                System.out.print(hostName + ": ");
                sendingMessage = scan.nextLine();

                // Inner message to target client
                String innerMessage = messagerToClient.encodeMessage(
                        Opcode.MESG,
                        sendingMessage
                );

                // Outer message for relay to relay
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


                // TEST: Force disconnects
                if("q".equalsIgnoreCase(sendingMessage)){
                    System.out.println("Client disconnecting");
                    break;
                }

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

    private static void AuthSessiontoRelay (Socket socket, PrintWriter out, BufferedReader in) throws Exception{
        if (socket.isConnected()) {
            String msgString;
            Message msg;
            HashMap<String, String> list;
            KeyPair dfkeyPair = KeyHandler.createDHKeyPair();
            PublicKey targetDF;
            int challenge1 = KeyHandler.createChallenge();
            int challenge2 = 0;

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
                        byte[] byteKey = list.get("DF Value").getBytes();
                        X509EncodedKeySpec X509publicKey = new X509EncodedKeySpec(byteKey);
                        KeyFactory kf = KeyFactory.getInstance("DiffieHellman");
                        targetDF = kf.generatePublic(X509publicKey);
                    } else { throw new InvalidMessageFormat(); }
                } 
                else {
                    System.out.println("Authentication failed: unexpected Opcode: " + msg.getOpcode());
                    throw new InvalidMessageFormat();
                }
            } else { throw new InvalidMessageFormat(); }

            // Derive session key
            sessionKey = KeyHandler.deriveSessionKey(dfkeyPair.getPrivate(), targetDF);

            // 3. Client -> Relay: Challenge 2 response, DF Value
            list = new HashMap<>();
            list.put("Challenge 2 Response", String.valueOf(challenge2));
            list.put("DF Value", dfkeyPair.getPublic().toString());

            msgString = messagerToRelay.encodeMessage(Opcode.SESR, MessageManager.createListBody(list));
            out.println(msgString);

            }

    }

    private static class MessageHandler extends Thread {
        private BufferedReader serverStream;

        public MessageHandler(BufferedReader serverStream) {
            this.serverStream = serverStream;
        }

        public void run() {
            try {
                String serverResponse; 
                while((serverResponse = serverStream.readLine()) != null) {
                    System.out.println(serverResponse);
                    System.out.println();
                }
            } catch(IOException e) {
                System.out.println("Server closed");
            }
        }


    }

}
