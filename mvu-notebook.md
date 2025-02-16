# 2/10/25:

# Phase 1: Wire Protocol & Data Structures

## Design Your Message Formats

### Custom Protocol
- **Define message types** (e.g., `CREATE_ACCOUNT`, `LOGIN`, `SEND_MESSAGE`, `READ_MESSAGES`, etc.).
- **Decide on headers** (message type, payload length) and field ordering.
- **Document the byte layout.**

### JSON Protocol
- **Define JSON object structures** with keys like `"action"`, `"data"`, etc.

## Develop Serialization/Deserialization Routines
- Create a library/module for converting Python objects into both the custom binary format and JSON strings.
- Implement tests to verify correctness.

---

# Phase 2: Server Implementation

## Basic Server Setup
- Create a TCP server that listens on a configurable port.
- Handle multiple clients (using threads or asyncio).

## Implement Business Logic

### Account Management
- Store accounts (using dictionaries or a simple database file).
- Implement password checks and secure transmission.

### Message Routing & Storage
- When a message is sent, check recipient availability; store if offline.
- Allow querying for unread messages and message deletion.

## Protocol Handling
- Write routines to parse incoming data for both protocol variants.
- Design your server to be protocol-agnostic where possible (e.g., a core service layer that works on parsed command objects).

---

# Phase 3: Client Implementation (with GUI)

## Develop a Tkinter-Based GUI

### Login/Account Creation Screen
- Form for entering a username and password.
- Logic to switch between “create account” and “login” based on server response.

### Main Chat Window
- Text area for displaying messages.
- Input fields/buttons for sending messages.
- Account listing with support for wildcards and pagination if needed.

## Networking Integration
- Use a background thread or asynchronous calls to communicate with the server.
- Ensure the GUI remains responsive while waiting for network operations.

## Configuration
- Allow the user to specify server connection details via a configuration file or command-line parameters.

---

# Phase 4: Testing & Performance Evaluation

## Unit & Integration Tests
- Write tests for the serialization/deserialization routines.
- Test server logic (account creation, login, message storage) using simulated client connections.
- Test the client GUI for basic usability (manual testing might be key here).

## Performance Comparison
- Measure the size and efficiency of messages using your custom protocol versus JSON.
- Log and document these findings in your engineering notebook.
- Reflect on how these differences might affect scalability and efficiency.

---

# Phase 5: Documentation & Code Review Preparation

## Engineering Notebook
- Document design decisions, protocol formats, testing strategies, and performance comparisons.

## Code Documentation
- Comment code thoroughly, explaining design choices.
- Write a README detailing how to run the server and client, configuration options, and protocol details.

## Test Coverage
- Ensure that unit tests cover critical functionality.

## Prepare for Code Reviews
- Organize your code repository and documentation.
- Prepare to both give and receive constructive feedback.

# 2/11/25:
- Serialization:
    - Using enums to encode operation types
    - Encode using utf-8
    - struct.pack to increase simplicity
    - Lists to increase space efficiency and simplicity
    - Unit tests

# **Engineering Notebook Entry – 2/12/25**
---

## **Observations & Programming Choices in Client Implementation**

### **1. Choice of Wire Protocol**
- **Custom Binary Serialization**: Instead of using JSON, I opted for a custom binary protocol to ensure **compactness, speed, and efficiency** when transmitting messages between the client and server.
- **Field Order and Encoding**:
    - Used **4-byte operation codes** (`Operations` enum) for clarity.
    - **Payload length** is included as a 4-byte integer for efficient parsing.
    - **UTF-8 encoding** is used for string-based data.
- **Why `struct.pack()`?**
    - **Simplicity**: `struct.pack` ensures precise control over message formatting.
    - **Performance**: More efficient than JSON parsing.
    - **Reliability**: Less prone to errors than delimiter-based string parsing.

---

### **2. Threading Considerations in Client**
- **Separate Thread for Receiving Messages**:
    - A dedicated thread continuously listens for incoming messages to ensure **non-blocking** execution.
    - This prevents message reception from interfering with UI interactions or user inputs.
- **Synchronization using Threading Events**:
    - Introduced `threading.Event()` to synchronize server responses.
    - This ensures that `send_message()` blocks until the appropriate response is received.

#### **Why use Events instead of just waiting?**
- Avoids busy-waiting (which wastes CPU cycles).
- Allows timeout-based handling for robustness.
- Simplifies debugging since responses are explicitly acknowledged.

---

### **3. Handling Server Responses Efficiently**
- **Operation-Based Routing**:
    - The function `handle_server_response()` routes responses based on the **operation type** (`Operations` enum).
    - Maintains a **consistent structure** for handling each operation.
- **Tracking the Current Operation**:
    - Used `self.current_operation` to track which request is awaiting a response.
    - Helps avoid **race conditions** when multiple requests are in flight.

#### **Why Track Operations?**
- Avoids unnecessary responses being processed when multiple requests are being handled concurrently.
- Ensures that each request-response pair is properly **matched and acknowledged**.

---

### **4. Security Considerations in Authentication**
- **SHA-256 with a Fixed Salt for Password Hashing**:
    - Chose SHA-256 (instead of bcrypt) for **simplicity and performance**.
    - Used a **fixed salt** to ensure that the hashing method remains deterministic across different runs.
    - *Note:* Fixed salts have security weaknesses (susceptibility to rainbow table attacks), so in the future, moving to **per-user salts** would be beneficial.

#### **Why not send plaintext passwords?**
- Always send **hashed passwords** to prevent eavesdropping risks.
- Avoids reliance on TLS for security (though TLS is still recommended for transport-layer encryption).

---

### **5. GUI Considerations in `gui_client.py`**
- **Ensuring UI Responsiveness**:
    - All **network interactions** (e.g., `list_accounts()`, `send_message()`) occur **in separate threads**.
    - Used `self.master.after(0, callback, args...)` to **update the UI from the main thread** and avoid `_tkinter.TclError`.
- **Separation of Concerns**:
    - The client class **only handles networking** and does not interact with the UI.
    - The GUI class calls the client methods but executes updates in a **safe manner** using `after()`.
- **Error Handling**:
    - Used **message boxes** (`messagebox.showerror()`, `messagebox.showinfo()`) to communicate failures and successes to users.
    - Ensured that every network call includes **timeout handling** to prevent UI freezes.

---

### **6. Debugging Considerations**
- **Verbose Logging**:
    - Included **print statements** when sending and receiving messages.
    - Logs server responses to make debugging **easier and more transparent**.
- **Graceful Error Handling**:
    - Implemented try-except blocks in networking functions to **catch and report errors**.
    - Used `sys.exit(1)` when failing to connect to the server, ensuring **clean termination**.

---

### **7. Future Improvements**
1. **Move to Asynchronous I/O (`asyncio`)**
    - Current threading model works, but moving to **async/await** could simplify event handling.
2. **Improve Security**
    - Use **per-user salts** instead of a fixed salt.
    - Implement **TLS encryption** to protect against man-in-the-middle attacks.
3. **Optimize Message Storage**
    - Currently, messages are stored **in-memory** on the server.
    - Consider **database-backed** storage (e.g., SQLite, PostgreSQL) for better **persistence** and **scalability**.

---

### **Summary**
✅ **Custom binary serialization** ensures compact, efficient data exchange.  
✅ **Threading with synchronization mechanisms** prevents race conditions.  
✅ **Event-based response handling** ensures correct message routing.  
✅ **UI responsiveness maintained using `after(0, callback)`** in Tkinter.  
✅ **Security-conscious authentication with hashed passwords** (though per-user salts needed for improvement).  

Overall, the current implementation provides a **functional, scalable, and efficient** chat client, with room for improvements in **security, asynchronous programming, and persistence**. 🚀

# Engineering Notebook – Serialization Comparison

## Serialization Protocols Compared

We built two serialization implementations for our client–server API:

1. **Custom Binary Protocol:**
   - Uses `struct.pack()` to create an 8-byte header (4 bytes unused, 4 bytes for payload length).
   - Encodes the message as a JSON object, then prepends the header.
   - Results in very compact messages.

2. **JSON Protocol:**
   - Simply encodes a JSON object into UTF-8 without additional binary packing.
   - More verbose due to the inherent overhead of JSON formatting.

## Test Results

The following table shows the sizes of the messages generated for various operations:

| Operation Code | Operation                  | Payload                        | Custom Serialization Size | JSON Serialization Size |
|---------------|----------------------------|--------------------------------|---------------------------|-------------------------|
| 11            | LOGIN                      | `['username', 'password']`     | 26 bytes                  | 65 bytes                |
| 15            | SEND_MESSAGE               | `['alice\nbob\nHello, Bob!']`  | 30 bytes                  | 68 bytes                |
| 14            | LIST_ACCOUNTS              | `['alice', 'user*']`           | 20 bytes                  | 59 bytes                |
| 16            | VIEW_UNDELIVERED_MESSAGES  | `['alice', '10']`              | 17 bytes                  | 56 bytes                |
| 13            | DELETE_ACCOUNT             | `['alice']`                    | 14 bytes                  | 50 bytes                |

## Analysis & Remarks

### Efficiency

- **Custom Binary Protocol:**
  - **Compactness:**
    - The custom protocol produces significantly smaller messages (e.g., 26 bytes vs. 65 bytes for LOGIN).
    - This efficiency comes from binary packing which avoids textual overhead.
  - **Performance:**
    - Lower message size translates to reduced network bandwidth usage and potentially lower latency, which is critical for real-time services.

- **JSON Protocol:**
  - **Ease of Use:**
    - JSON is human-readable and easier to debug and extend.
  - **Overhead:**
    - The additional bytes (e.g., extra quotation marks, braces, commas) increase the message size, which may add up in high-volume applications.

### Scalability

- **Bandwidth:**
  - With a high number of messages, even a difference of 10–40 bytes per message can lead to significant savings in network bandwidth when using the custom protocol.
- **Latency:**
  - Smaller messages reduce the transmission delay per message. In a chat service with thousands of messages per minute, this efficiency may reduce overall latency.
- **Maintainability & Interoperability:**
  - JSON’s verbosity is a trade-off for ease of development, interoperability, and debugging.
  - The custom protocol is more efficient but may require more careful versioning and stricter documentation.

### Trade-offs

- **Custom Serialization:**
  - **Pros:**
    - Compact: Less bandwidth usage and lower latency.
    - Efficient: Faster parsing in high-volume scenarios.
  - **Cons:**
    - Less readable: Harder to debug without specialized tools.
    - Less flexible: Changing the protocol may be more challenging.

- **JSON Serialization:**
  - **Pros:**
    - Human-readable: Easier to debug and integrate with other systems.
    - Flexible: Simple to extend or modify the message format.
  - **Cons:**
    - Less efficient: Larger message sizes can lead to increased network usage and latency in extreme scenarios.

## Conclusion

Our tests show that the custom binary protocol is much more efficient in terms of message size, making it a better choice for high-throughput, low-latency systems. However, the JSON approach offers significant advantages in terms of readability, ease of debugging, and flexibility. The choice between these protocols should be guided by the specific requirements of the service:

- **Use Custom Serialization** when bandwidth and latency are at a premium, and you can invest in tooling for debugging.
- **Use JSON Serialization** when ease of development, maintainability, and interoperability are more critical.

These results and observations will guide our decisions regarding efficiency and scalability in our service architecture.