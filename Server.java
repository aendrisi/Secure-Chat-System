/* CS6349 Network Security: Secure Relay-Based Chat System
 * By Parisa Nawar (pxn210032) and Aendri Singh (axs210369)
 * 
 * Code for the Relay server
 */


import java.io.*;
import java.util.Base64;
import java.util.Random;
import java.util.concurrent.*;

import javax.crypto.SecretKey;

import java.net.*;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.PublicKey;
import java.security.spec.X509EncodedKeySpec;

public class Server {
    private static final String RELAY_NAME = "Relay";
    //private static String serverHost = "localhost";
    private static int serverPort = 1025;
    private static ConcurrentHashMap<String, ClientHandler> client = new ConcurrentHashMap<>();
    private static ConcurrentHashMap<Integer, PublicKey> uidKeyMap = new ConcurrentHashMap<>();
    private static ConcurrentHashMap<String, Integer> hostUIDMap = new ConcurrentHashMap<>();
    private static Random random = new Random();
    private static KeyPair kp;

    public static void main(String[] args) throws InterruptedException {
        System.out.println("Server is running");
        KeyHandler keyhand = new KeyHandler(); 

        // Generate Public and Private Keys
        try {
            kp = KeyHandler.createRSAKeyPair(RELAY_NAME);
        } catch (Exception e) {
            System.out.println("Error: Unable to create key pair! " + e);
            e.printStackTrace();
            return;
        }
        
        try(ServerSocket serverSocket = new ServerSocket(serverPort)) {
            //Alice connects to the server
            System.out.println("A has yet to connect...");
            Socket aSocket = serverSocket.accept();
            ClientHandler aHandler;
            try {
               aHandler = new ClientHandler(aSocket, "Alice", kp);
            } catch (Exception e) {
                System.out.println("ERROR: Unable to find client Alice's public key!");
                return;
            }
            
            client.put("Alice", aHandler);
            aHandler.start();

            //Bob connects to the server
            System.out.println("B  has yet to connect...");
            Socket bSocket = serverSocket.accept();
            ClientHandler bHandler;
            try {
               bHandler = new ClientHandler(bSocket, "Bob", kp);
            } catch (Exception e) {
                System.out.println("ERROR: Unable to find client Bob's public key!");
                return;
            }
            client.put("Bob", bHandler);
            bHandler.start();

            System.out.println("Both clients are connected to the server.");
            //aHandler.sendClientMessage("You have been connected to the other client.");
            //bHandler.sendClientMessage("You have been connected to the other client.");

            while(aHandler.isAlive() || bHandler.isAlive()) {
                Thread.sleep(1000);
            }
        } catch(IOException e) {
            System.err.println("Exception: " + e.getMessage());
            e.printStackTrace();
        } finally {
            System.out.println("Server terminated");
        }
    }

    //register client and add uid
    public static int registerClient(String hostname, String encodedPublicKey) throws Exception {
        byte[] byteKey = Base64.getDecoder().decode(encodedPublicKey);
        X509EncodedKeySpec X509publicKey = new X509EncodedKeySpec(byteKey);
        KeyFactory kf = KeyFactory.getInstance("RSA");
        PublicKey publicKey = kf.generatePublic(X509publicKey);
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

    public static void relay(String sender, String msg) {
            String receiver = "";
            if(sender.equals("Alice")) { 
                receiver = "Bob";
            } else {
                receiver = "Alice";
            }

            ClientHandler receiverHandler = client.get(receiver);
            if(receiverHandler != null) {
                receiverHandler.sendClientMessage(sender + ": " + msg);
            } 
    }

    // Relays the message to the receiver
    public static void relay(Message msg) {
        String sender = msg.getSender();
        String receiver = msg.getReceiver();
        
        // **** Aendri: I think we can make the client threads persistent by storing
        //              them somewhere 
        ClientHandler receiverHandler = client.get(receiver);
        if(receiverHandler != null) {
            receiverHandler.sendClientMessage(sender + ": " + msg.getBody());
        } 
    }

    //Communicate server to client 
    private static class ClientHandler extends Thread {
        private Socket clientSocket;
        private String clientID;
        private PrintWriter out;
        private BufferedReader in;

        private KeyPair relayKeys;
        private PublicKey clientKey;
        private SecretKey sessionKey;

        public ClientHandler(Socket socket, String clientID, KeyPair keys) throws UnknownUser {
            this.clientSocket = socket;
            this.clientID = clientID;
            this.relayKeys = keys;

            clientKey = KeyHandler.findPublicKey(clientID);
        }

        public void run() {
            try {
                out = new PrintWriter(clientSocket.getOutputStream(), true);
                in = new BufferedReader(new InputStreamReader(clientSocket.getInputStream()));
                MessageManager relayToClient = new MessageManager(
                    RELAY_NAME, relayKeys.getPrivate(), clientID, clientKey);

                String input; 

                while ((input = in.readLine()) != null) {
                    System.out.println("Received from " + clientID + ": " + input);
                    
                    // Decode message
                    try {
                        Message inputMessage = new Message(input);

                        if(inputMessage.getOpcode() == Opcode.REGI) {
                            String encodedPublicKey = inputMessage.getBody();
                            int uid = Server.registerClient(clientID, encodedPublicKey);
                            System.out.println("Client " + clientID + " new UID: " + uid);
                            out.println("UID:" + uid);
                        } else {
                            System.out.println(
                            inputMessage.getSender() + " to " + inputMessage.getReceiver() +
                            ": " + inputMessage.getBody());
                            Server.relay(inputMessage);
                        }

                    } catch (InvalidMessageFormat e) {
                        System.out.println("ERROR: MESSAGE FORMAT INVALID!");
                    } catch (Exception e) {
                        System.out.println("ERROR: Something else is wrong with the message!");
                    }
                }

            } catch(IOException e) {
                System.err.println(clientID + " " + e.getMessage());
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

                    client.remove(clientID);

                } catch(IOException e) {
                    System.err.println(clientID + " " + e.getMessage());
                }
            }
        }

        public void sendClientMessage(String msg) {
        if(out != null) {
            String[] parts = msg.split("Opcode: ");
            if (parts.length > 1) {
                //String opcode = parts[1].split(" ")[0];
                String[] msgbody = msg.split("Body: ");
                String body = msgbody[1].trim();
                out.println(body);
            } else { 
                out.println(msg);
            }
        }
    }
    }
}