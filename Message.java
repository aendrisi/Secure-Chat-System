/* CS6349 Network Security: Secure Relay-Based Chat System
 * By Parisa Nawar (pxn210032) and Aendri Singh (axs210369)
 * 
 * Message Class: A message object
 */

import java.time.LocalDateTime;

// Signifies the type of message and determines how it will be read/interpreted by the system. 
enum Opcode {
    REGI, // Registration
    SESR, // Establish Session Key with Relay
    SESC, // Establish Session Key with Client
    MESG, // Client chat message
    ERSR, // Error: Session Key with Replay Expired/Invalid
    ERSC, // Error: Session Key with Recipient Client Expired/Invalid
    ERRM, // Error: Message Invalid
    ERNF, // Error: Recipient Not Found
    ERRR  // Error: Registration Invalid
}

public class Message {
    private final int NUM_REQUIRED_HEADERS = 5;
    // HEADERS:
    private Opcode opcode;
    private String sender;
    private String receiver;
    private LocalDateTime timestamp;
    private int size = 0;
    private int sessionID = -1;
    private String body;

    // Create message with NO body
    public Message (Opcode opcode, String sender, String receiver) {
        this.opcode = opcode;
        this.sender = sender;
        this.receiver = receiver;

        timestamp = LocalDateTime.now();
    }

    // Create message WITH body
    public Message (Opcode opcode, String sender, String receiver, String body) {
        this.opcode = opcode;
        this.sender = sender;
        this.receiver = receiver;
        this.body = body;

        timestamp = LocalDateTime.now();
        size = body.length();
    }

    // Decode and create message
    public Message (String message) throws Exception{
        String[] headers = message.split(" - ", NUM_REQUIRED_HEADERS + 1);

        // Verify number of headers
        if (headers.length < NUM_REQUIRED_HEADERS) { throw new InvalidMessageFormat(); }

        // Parse required headers
        for (int i = 0; i < NUM_REQUIRED_HEADERS; i++) {
            String[] parts = headers[i].split(": ", 2);
            
            if (parts[0].equals("Opcode")) {
                opcode = Opcode.valueOf(parts[1]);
            }
            else if (parts[0].equals("Sender")) {
                sender = parts[1];
            } 
            else if (parts[0].equals("Receiver")) {
                receiver = parts[1];
            } 
            else if (parts[0].equals("Timestamp")) {
                timestamp = LocalDateTime.parse(parts[1]);
            } 
            else if (parts[0].equals("Size")) {
                size = Integer.parseInt(parts[1]);
            }
            else {
                throw new InvalidMessageFormat();
            }
        }

        // Parse optional headers
        if (headers.length > NUM_REQUIRED_HEADERS) {
            // session id
            int headerPos = headers[NUM_REQUIRED_HEADERS].indexOf(": ");
            if (headerPos > 0) {
                String header = headers[NUM_REQUIRED_HEADERS].substring(0, headerPos);
                if (header.equals("SessionID")) {
                    sessionID = Integer.parseInt(header.substring(0, header.indexOf("\n")));
                }
            }

            // body
            if (size > 0) {
                headerPos = headers[NUM_REQUIRED_HEADERS].indexOf("Body: ");
                body = headers[NUM_REQUIRED_HEADERS].substring(headerPos + 6);
            } 
        } 
        // Body header missing!
        else if (size > 0) {
            throw new InvalidMessageFormat();
        }
    }

    // Sets the sessionID
    public void setSessionID (int sessionID) {
        this.sessionID = sessionID;
    }

    // Returns the message in string format
    public String toString() {
        String message = 
            "Opcode: " + opcode.name() + " - " +
            "Sender: " + sender + " - " +
            "Receiver: " + receiver + " - " +
            "Timestamp: " + timestamp + " - " +
            "Size: " + size + " - ";

            if (sessionID > 0) {
                message += "SessionID: " + sessionID + " - ";
            }

            if (size > 0) {
                message += "Body: " + body;
            }

        return message;
    }

    public Opcode getOpcode() { return opcode; }
    public String getSender() { return sender; }
    public String getReceiver() { return receiver; }
    public LocalDateTime getTimestamp() { return timestamp; }
    public int getSize() { return size; }
    public int getSessionID() { return sessionID; }
    public String getBody() { return body; }
}

// Exception for invalid message formats
class InvalidMessageFormat extends Exception {
    public InvalidMessageFormat() {
        super();
    }
    public InvalidMessageFormat(String m) {
        super(m);
    }
}