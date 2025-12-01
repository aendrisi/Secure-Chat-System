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
        
        ClientHandler receiverHandler = client.get(receiver);
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
    }

    //Communicate server to client 
    private static class ClientHandler extends Thread {
        private Socket clientSocket;
        private String clientID;
        private int uid;
        private PrintWriter out;
        private BufferedReader in;
        private MessageManager relayToClient;

        private KeyPair relayKeys;
        private PublicKey clientKey;
        private SecretKey sessionKey;
        HashMap<String, String> list;

        // SESSION SETUP
        private int stateSESR = 0;
        private int challenge1 = 0;
        private int challenge2 = KeyHandler.createChallenge();
        KeyPair dfkeyPair;

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
                relayToClient = new MessageManager(
                    RELAY_NAME, relayKeys.getPrivate(), clientID, clientKey);

                String input; 

                while ((input = in.readLine()) != null) {
                    //System.out.println("Received from " + clientID + ": " + input);
                    
                    // Encode message
                    try {
                        Message inputMessage = new Message(input);

                        // REGISTRATION
                        if(inputMessage.getOpcode() == Opcode.REGI) {
                            String encodedPublicKey = inputMessage.getBody();
                            uid = Server.registerClient(clientID, encodedPublicKey);
                            System.out.println("Client " + clientID + " new UID: " + uid);
                            //out.println("UID:" + uid);
                            String uidMessage = relayToClient.encodeMessage(
                                Opcode.REGI,
                                String.valueOf(uid)
                            );

                            out.println(uidMessage);
                            
                        } 
                        // SESSION KEY: Client to Relay
                        else if (inputMessage.getOpcode() == Opcode.SESR) {
                            //System.out.println("Authenticating and Session Setup with " + clientID);
                            String body = inputMessage.getBody();
                            if (stateSESR != 1) {
                                // 1. Client -> Relay: Challenge 1
                                list = MessageManager.readListBody(body);

                                // Get Challenge 1
                                if (list.containsKey("Challenge 1")) {
                                    challenge1 = Integer.parseInt(list.get("Challenge 1"));
                                } else { throw new InvalidMessageFormat(); }

                                // 2. Relay -> Client: Challenge 1 response, Challenge 2, Diffie-Hellman public value
                                dfkeyPair = KeyHandler.createDHKeyPair(); // create keypair

                                list = new HashMap<>();
                                list.put("Challenge 1 Response", String.valueOf(challenge1));
                                list.put("Challenge 2", String.valueOf(challenge2));
                                list.put("DF Value", KeyHandler.convertDFPubKeytoString(dfkeyPair.getPublic()));

                                String msgString = relayToClient.encodeMessage(Opcode.SESR, MessageManager.createListBody(list));
                                out.println(msgString);
                                
                                stateSESR = 1; 
                                relayToClient.resetSession();
                            } 
                            // 3. Client -> Relay: Challenge 2 response, DF Value
                            else {
                                list = MessageManager.readListBody(body);

                                // Verify Challenge 2 response
                                if (list.containsKey("Challenge 2 Response")) {
                                    int resp = Integer.parseInt(list.get("Challenge 2 Response"));
                                    if (challenge2 != resp) {
                                        throw new CannotVerifyIntegrity();
                                    }
                                } else { throw new InvalidMessageFormat(); }
                                // Get D-F public value
                                if (list.containsKey("DF Value")) {
                                    PublicKey clientDF = KeyHandler.convertStringtoDFPubKey(list.get("DF Value"));
                                    sessionKey = KeyHandler.deriveSessionKey(dfkeyPair.getPrivate(), clientDF); // Derive Session key
                                } else { throw new InvalidMessageFormat(); }
                                
                                System.out.println("Authenticating and Session Setup with " + clientID);
                                relayToClient.setSession(sessionKey, uid); // SessionID = UID
                                stateSESR = 0;
                            }
                        }
                        // SESSION KEY: Client to Client
                        else if (inputMessage.getOpcode() == Opcode.SESC) {
                            System.out.println("Relaying SESC message from " + inputMessage.getSender() + " to " + inputMessage.getReceiver());
                            Server.relay(inputMessage);
                        }
                        // MESSAGE: Client to Client
                        else if (inputMessage.getOpcode() == Opcode.MESG) {
                            System.out.println(
                            inputMessage.getSender() + " to " + inputMessage.getReceiver() +
                            ": " + inputMessage.getBody());
                            Server.relay(inputMessage);
                        }
                        else {
                            System.out.println(inputMessage.getOpcode().toString());
                            Server.relay(inputMessage);
                        }

                    } catch (InvalidMessageFormat e) {
                        System.out.println("ERROR: MESSAGE FORMAT INVALID!");
                        e.printStackTrace();
                    } catch (Exception e) {
                        System.out.println("ERROR: Something else is wrong with the message!");
                        e.printStackTrace();
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
                /**String[] parts = msg.split("Opcode: ");
                if (parts.length > 1) {
                    //String opcode = parts[1].split(" ")[0];
                    String[] msgbody = msg.split("Body: ");
                    String body = msgbody[1].trim();
                    out.println(body);
                } else { 
                    out.println(msg);
                }*/

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