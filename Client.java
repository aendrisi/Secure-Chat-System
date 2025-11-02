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
import java.util.Base64;
import java.util.List;

public class Client {
    private static final String RELAY_NAME = "Relay";
    private static String serverHost = "localhost";
    private static int serverPort = 1025; 
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
            //messageHandler.start(); 

            // User to Relay communication: 
            MessageManager messagerToRelay;
            try {
                messagerToRelay = new MessageManager(hostName, kp.getPrivate(), RELAY_NAME);
            } catch (Exception e) {
                System.out.println("Unable to locate Relay server's public key! " + e);
                scan.close();
                KeyHandler.deletePublicKey(hostName);
                return;
            }
            
            // STAGE 1: Registration
            String encodedPublicKey = Base64.getEncoder().encodeToString(kp.getPublic().getEncoded());
            System.out.println("REGISTRATION STAGE");

            //create registration message 
            String regMessage = messagerToRelay.encodeMessage(
                Opcode.REGI,
                encodedPublicKey
            );

            out.println(regMessage);
            String serverResponse = in.readLine();
            
            if(serverResponse != null) {
                //Get the UID from server
                String trimmedResponse = serverResponse.trim();
                if(trimmedResponse.startsWith("UID:")) {
                    try {  
                        //store the uid
                        uid = Integer.parseInt(trimmedResponse.substring(4).trim());
                        System.out.println("Registration successful. Received UID: " + uid);
                    } catch(NumberFormatException e) {
                        System.out.println("Registration failed: Invalid UID format");
                        scan.close();
                        return;
                    }
                } else {
                    System.out.println("Registration failed: Did not receive expected UID response");
                    scan.close();
                    return;
                }
            } else {
                System.out.println("Registration failed: null response.");
                scan.close();
                return;
            }

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

            String sendingMessage;

            // STAGE 1: Registration


            // STAGE 2.1: Authentication and Session Setup with RELAY
            // ...
            //System.out.println("Skipping STAGE 2.1");
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
                        // End program
                        System.out.println("See ya!");
                        scan.close();
                        KeyHandler.deletePublicKey(hostName);
                        return;
                    }
                }
            } while (!success);

            // User to target client 
            MessageManager messagerToClient = new MessageManager(
                    hostName, kp.getPrivate(), 
                    target, targetKey);
            
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
                        target,
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
