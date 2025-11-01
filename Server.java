/* CS6349 Network Security: Secure Relay-Based Chat System
 * By Parisa Nawar (pxn210032) and Aendri Singh (axs210369)
 * 
 * Code for the Relay server
 */


import java.io.*;
import java.util.concurrent.*;

import javax.crypto.SecretKey;

import java.net.*;
import java.security.KeyPair;
import java.security.PublicKey;

public class Server {
    private static final String RELAY_NAME = "Relay";
    //private static String serverHost = "localhost";
    private static int serverPort = 1025;
    private static ConcurrentHashMap<String, ClientHandler> client = new ConcurrentHashMap<>();

    public static void main(String[] args) throws InterruptedException {
        System.out.println("Server is running");
        KeyHandler keyhand = new KeyHandler(); 

        // Generate Public and Private Keys
        try {
            keyhand.setUser(RELAY_NAME);
            keyhand.createKeyPair();
        } catch (Exception e) {
            System.out.println("Error: Unable to create key pair! " + e);
            return;
        }
        
        try(ServerSocket serverSocket = new ServerSocket(serverPort)) {
            //Alice connects to the server
            System.out.println("A has yet to connect...");
            Socket aSocket = serverSocket.accept();
            ClientHandler aHandler = new ClientHandler(aSocket, "Alice", keyhand.getKeyPair());
            client.put("Alice", aHandler);
            aHandler.start();

            //Bob connects to the server
            System.out.println("B  has yet to connect...");
            Socket bSocket = serverSocket.accept();
            ClientHandler bHandler = new ClientHandler(bSocket, "Bob",  keyhand.getKeyPair());
            client.put("Bob", bHandler);
            bHandler.start();

            System.out.println("Both clients are connected to the server.");
            aHandler.sendClientMessage("You have been connected to the other client.");
            bHandler.sendClientMessage("You have been connected to the other client.");

            while(aHandler.isAlive() || bHandler.isAlive()) {
                Thread.sleep(1000);
            }
        } catch(IOException e) {
            System.err.println("Exception: " + e.getMessage());
        } finally {
            System.out.println("Server terminated");
        }
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

        public ClientHandler(Socket socket, String clientID, KeyPair keys) throws FileNotFoundException{
            this.clientSocket = socket;
            this.clientID = clientID;
            this.relayKeys = keys;

            // Find client's public key
            KeyHandler keyhand = new KeyHandler();
            clientKey = keyhand.getUserPublicKey(clientID);

            // Check if destination public key was found
            if (clientKey == null) {
                throw new FileNotFoundException();
            }
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
                        System.out.println(
                            inputMessage.getSender() + " to " + inputMessage.getReceiver() +
                            ": " + inputMessage.getBody());
                        Server.relay(inputMessage);

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
            out.println(msg);
        }
    }
    }
}