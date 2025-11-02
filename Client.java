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
    private static String uid;
    private static SecretKey sessionKey;


    public static void main(String[] args) {
        Scanner scan = new Scanner(System.in);
        KeyHandler keyhand = new KeyHandler();

        System.out.print("Enter your username (no spaces): ");
        hostName = scan.next();

        if (scan.hasNextLine()) { scan.nextLine(); } // Clear buffer


        //Set user
        try {
            if (keyhand.setUser(hostName)) {
                System.out.println("Welcome " + hostName + "!");
            } else {
                System.out.println("Welcome back " + hostName + "!");
            }
        } catch (Exception e) {
            System.out.println("Unable to open file! " + e);
        }

        // Create an RSA key pair
        try {
            keyhand.createKeyPair();
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
            messageHandler.start(); 

            // User to Relay communication: 
            MessageManager messagerToRelay = new MessageManager(
                hostName, keyhand.getKeyPair().getPrivate(), RELAY_NAME);
            
            String sendingMessage;

            // STAGE 1: Registration
            try {
                uid = keyhand.getUID(hostName);
                if(uid == null) {
                    uid = java.util.UUID.randomUUID().toString();
                    System.out.println("Generated new uid" + uid);
                } else {
                    System.out.println("Using existing uid" + uid);
                }

                keyhand.setUID(uid);
                String pubKey = Base64.getEncoder().encodeToString(keyhand.getKeyPair().getPublic().getEncoded());
                String msgBody = "UID=" + uid + " | PublicKey=" + pubKey;
                String regMessage = messagerToRelay.encodeMessage(
                    Opcode.REGI,
                    hostName,
                    RELAY_NAME,
                    msgBody
                );

                out.println(regMessage);

            } catch(Exception e) {
                System.out.println("UID registration failed" + e.getMessage());
                scan.close();
                return;
            }


            // STAGE 2.1: Authentication and Session Setup with RELAY
            // ...

            // Stage 2.15: CHOSING A CLIENT!
            String target;
            PublicKey targetKey = null;
            boolean success = false;

            // Select destination
            do {
                // Users found
                List<String> users = keyhand.getAvailableUsers();
                if (!users.isEmpty()) {
                    System.out.println("Who do you want to talk to?");
                    for (String user : users) {
                        System.out.println(user);
                    }
                    System.out.print("Choose (case sensitive): ");
                    target = scan.next();
                    if (scan.hasNextLine()) { scan.nextLine(); } // Clear buffer

                    // Verify chosen user
                    targetKey = keyhand.getUserPublicKey(target);
                    if (targetKey == null) {
                        System.out.println("Dunno who that is.");
                        success = false;
                    } else {
                        success = true;
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
                        return;
                    }
                }
            } while (!success);

            // User to target client 
            MessageManager messagerToClient = new MessageManager(
                    hostName, keyhand.getKeyPair().getPrivate(), 
                    target, targetKey);
            
            // STAGE 2.2: Authentication and Session Setup with CLIENT
            // ...
            try {
                KeyPair userDKP;
                KeyPair targetDKP; // TEST: should be replaced with the public key from the target
                
                KeyPairGenerator kpg = KeyPairGenerator.getInstance("DiffieHellman");
                KeyAgreement keyAgreement = KeyAgreement.getInstance("DiffieHellman");
                kpg.initialize(512);
                
                // Generate diffie-hellman key pairs
                userDKP = kpg.generateKeyPair();
                targetDKP = kpg.generateKeyPair();

                // Derive shared secret  
                keyAgreement.init(userDKP.getPrivate()); // USER private key
                keyAgreement.doPhase(targetDKP.getPublic(), true); // TARGET public key
                byte[] sharedSecretBytes = keyAgreement.generateSecret();
                
                // Convert secret key
                sessionKey = new SecretKeySpec(sharedSecretBytes, 0, sharedSecretBytes.length, "AES");
                //uid = 5; // TEST: should be given by the Relay

                messagerToClient.setSession(sessionKey, uid);
            } catch (Exception e) {} 
            

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
                /**System.out.println("---- INNER ----\n" + 
                                    sendingMessage +
                                    "\n---- INNER ----\n");*/
                try {
                    //Message testMess = messagerToRelay.decodeMessage(test);
                    //test = testMess.toString();
                    /**System.out.println("---- OUTER ----\n" + 
                                        outerMessage +
                                        "\n---- OUTER ----\n");*/
                } catch (Exception e) {
                    System.out.println("ERROR: " + e);
                } 
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
