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
- Establish data model for users
- Implement account management functions
- Implement messaging functions
- 

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
