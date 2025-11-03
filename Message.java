/* CS6349 Network Security: Secure Relay-Based Chat System
 * By Parisa Nawar (pxn210032) and Aendri Singh (axs210369)
 * 
 * Message Class: Stores information on a message 
 */

import java.time.LocalDateTime;

/**
 * Signifies the type of message and determines how it will be read/interpreted by the system.
 */
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

/**
 * The Message class stores header and body information on a message.
 */
public class Message {
    private final int NUM_REQUIRED_HEADERS = 5;
    private final String HEADER_SEPERATOR = " - ";
    // HEADERS:
    private Opcode opcode;
    private String sender;
    private String receiver;
    private LocalDateTime timestamp;
    private int size = 0;
    private int sessionID = -1;
    private String body;

    /**
     * Creates a message object with no body.
     * @param opcode Message type
     * @param sender The original sender of the message 
     * @param receiver The final receipient of the message
     */
    public Message (Opcode opcode, String sender, String receiver) {
        this.opcode = opcode;
        this.sender = sender;
        this.receiver = receiver;

        timestamp = LocalDateTime.now();
    }

    /**
     * Creates a message object with a body.
     * @param opcode Message type
     * @param sender The original sender of the message 
     * @param receiver The final receipient of the message
     * @param body The message's contents
     */
    public Message (Opcode opcode, String sender, String receiver, String body) {
        this.opcode = opcode;
        this.sender = sender;
        this.receiver = receiver;
        this.body = body;

        timestamp = LocalDateTime.now();
        size = body.length();
    }

    /**
     * Decodes a message string and creates a message object.
     * @param message The message in string format
     * @throws Exception Indicates an invalid message format
     */
    public Message (String message) throws Exception{
        String[] headers = message.split(HEADER_SEPERATOR, NUM_REQUIRED_HEADERS + 1);

        // Verify number of headers
        if (headers.length < NUM_REQUIRED_HEADERS) { throw new InvalidMessageFormat(); }

        // Parse required headers
        for (int i = 0; i < NUM_REQUIRED_HEADERS; i++) {
            String[] parts = headers[i].split(": ", 2);
            
            // OPCODE
            if (parts[0].equals("Opcode")) {
                opcode = Opcode.valueOf(parts[1]);
            }
            // SENDER
            else if (parts[0].equals("Sender")) {
                sender = parts[1];
            } 
            // RECEIVER
            else if (parts[0].equals("Receiver")) {
                receiver = parts[1];
            } 
            // TIMESTAMP
            else if (parts[0].equals("Timestamp")) {
                timestamp = LocalDateTime.parse(parts[1]);
            } 
            // SIZE
            else if (parts[0].equals("Size")) {
                size = Integer.parseInt(parts[1]);
            }
            // Unknown header
            else {
                throw new InvalidMessageFormat();
            }
        }

        // OPTIONAL HEADERS:
        if (headers.length > NUM_REQUIRED_HEADERS) {
            // SESSION ID
            int headerPos = headers[NUM_REQUIRED_HEADERS].indexOf(": ");
            if (headerPos > 0) {
                String header = headers[NUM_REQUIRED_HEADERS].substring(0, headerPos);
                if (header.equals("SessionID")) {
                    // If end of session ID found
                    int sessEnd = headers[NUM_REQUIRED_HEADERS].indexOf(HEADER_SEPERATOR);
                    if (sessEnd > 0) {
                        String sessionIDString = headers[NUM_REQUIRED_HEADERS].substring(header.length() + 2, sessEnd).trim();
                        sessionID = Integer.parseInt(sessionIDString);
                    } 
                    else { throw new InvalidMessageFormat("Missing SessionID end.");  }   
                }
            } 
        } 
        // BODY
        if (size > 0) {
            // If optional header exists
            if (headers.length > NUM_REQUIRED_HEADERS) {
                int headerPos = headers[NUM_REQUIRED_HEADERS].indexOf("Body: ");
                // If body header is found
                if (headerPos >= 0) {
                    body = headers[NUM_REQUIRED_HEADERS].substring(headerPos + 6);
                }
                else { throw new InvalidMessageFormat("Missing Body header.");  }
            } 
            else { throw new InvalidMessageFormat("Missing Body header.");  }
        }
    }

    /**
     * Sets the sessionID to the given values.
     * @param sessionID
     */
    public void setSessionID (int sessionID) {
        this.sessionID = sessionID;
    }

    /**
     * Returns the message object in string format.
     */
    public String toString() {
        String message = 
            "Opcode: " + opcode.name() + HEADER_SEPERATOR +
            "Sender: " + sender + HEADER_SEPERATOR +
            "Receiver: " + receiver + HEADER_SEPERATOR +
            "Timestamp: " + timestamp + HEADER_SEPERATOR +
            "Size: " + size + HEADER_SEPERATOR;

            if (sessionID > 0) {
                message += "SessionID: " + sessionID + HEADER_SEPERATOR;
            }

            if (size > 0) {
                message += "Body: " + body;
            }

        return message;
    }

    /**
     * Returns the opcode of the message. 
     * @return Opcode
     */
    public Opcode getOpcode() { return opcode; }

    /**
     * Returns the original sender of the message.
     * @return Sender
     */
    public String getSender() { return sender; }

    /**
     * Returns the final receipient of the message.
     * @return Receiver
     */
    public String getReceiver() { return receiver; }

    /**
     * Returns the timestamp of the message.
     * @return Timestamp
     */
    public LocalDateTime getTimestamp() { return timestamp; }

    /**
     * Returns the size of the message body.
     * @return Size
     */
    public int getSize() { return size; }

    /**
     * Returns the SessionID of the message. 
     * -1 if sessionID doesn't exist.
     * @return SessionID
     */
    public int getSessionID() { return sessionID; }

    /**
     * Returns the message body of the message.
     * @return Body
     */
    public String getBody() { return body; }
}

/**
 * Exception if invalid message formats.
 */
class InvalidMessageFormat extends Exception {
    /**
     * Invalid message format.
     */
    public InvalidMessageFormat() {
        super();
    }

    /**
     * Invalid message format.
     * @param m Display message
     */
    public InvalidMessageFormat(String m) {
        super(m);
    }
}