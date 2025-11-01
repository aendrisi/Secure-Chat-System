import java.io.*;
import java.util.concurrent.*;
import java.net.*;

public class Server {
    //private static String serverHost = "localhost";
    private static int serverPort = 1025;
    private static ConcurrentHashMap<String, ClientHandler> client = new ConcurrentHashMap<>();
    public static void main(String[] args) throws InterruptedException {
        System.out.println("Server is running");

        try(ServerSocket serverSocket = new ServerSocket(serverPort)) {
            //Alice connects to the server
            System.out.println("A has yet to connect...");
            Socket aSocket = serverSocket.accept();
            ClientHandler aHandler = new ClientHandler(aSocket, "Alice");
            client.put("Alice", aHandler);
            aHandler.start();

            //Bob connects to the server
            System.out.println("B  has yet to connect...");
            Socket bSocket = serverSocket.accept();
            ClientHandler bHandler = new ClientHandler(bSocket, "Bob");
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

    //Communicate server to client 
    private static class ClientHandler extends Thread {
        private Socket clientSocket;
        private String clientID;
        private PrintWriter out;
        private BufferedReader in;

        public ClientHandler(Socket socket, String clientID) {
            this.clientSocket = socket;
            this.clientID = clientID;
        }

        public void run() {
            try {
                out = new PrintWriter(clientSocket.getOutputStream(), true);
                in = new BufferedReader(new InputStreamReader(clientSocket.getInputStream()));
                String input; 

                while ((input = in.readLine()) != null) {
                    System.out.println("Received from " + clientID + ": " + input);
                    Server.relay(clientID, input);
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