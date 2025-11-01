import java.io.*;
import java.util.concurrent.*;
import java.net.*;
import java.util.Scanner;

public class Client {
    private static String serverHost = "localhost";
    private static int serverPort = 1025; 

    public static void main(String[] args) {
        Scanner scan = new Scanner(System.in);
        System.out.print("Are you Alice or Bob? Type the name with the exact case.");
        String clientID = scan.nextLine();

        try (
            Socket socket = new Socket(serverHost, serverPort);
            PrintWriter out = new PrintWriter(socket.getOutputStream(), true);
            BufferedReader in = new BufferedReader(new InputStreamReader(socket.getInputStream()));
        ) {
            System.out.println("Server connected");

            MessageHandler messageHandler = new MessageHandler(in);
            messageHandler.start(); 

            String sendingMessage;

            while(true) {
                sendingMessage = scan.nextLine();

                if("q".equalsIgnoreCase(sendingMessage)){
                    System.out.println("Client disconnecting");
                    break;
                }

                out.println(sendingMessage);
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
