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

# 2/26/25

# Implementing gRPC

## Client-Side Perspective

- **Ease of Development:**
  - **Simplification:** Using gRPC and Protocol Buffers greatly simplifies network communication on the client side. Instead of handling raw socket connections and custom serialization, you work with generated stubs and well-defined methods.
  - **Learning Curve:** There is an initial learning curve (e.g., understanding streaming, metadata, and deadlines), but overall it makes development more straightforward once you’re familiar with it.

- **Data Size Impact:**
  - **Overhead:** The data passed is now structured in a well-defined format (Protocol Buffers) which adds a small overhead compared to raw data. However, the benefits of type safety and schema evolution usually outweigh this cost.
  - **Efficiency:** Protobufs are highly efficient in size and speed, so the increase in data size is minimal.

- **Changes in Client Structure:**
  - **Abstraction:** The client no longer deals with low-level socket programming. Instead, it interacts with a high-level API generated from the `.proto` files.
  - **Modularity:** Code is now more modular; for instance, login, account management, and message streaming are clearly separated into dedicated RPC calls.
  - **Error Handling:** With gRPC, error handling is integrated into the RPC mechanism, which can simplify the client’s error management logic.

- **Impact on Testing:**
  - **Unit Testing:** Testing becomes easier because you can mock the gRPC stubs instead of simulating raw socket behavior.
  - **Integration Testing:** The integration tests need to account for gRPC’s behavior (such as streaming and deadlines), but overall tests tend to be more reliable due to the standardized communication protocol.
  - **Isolation:** It is simpler to isolate client logic since you are no longer testing custom serialization logic.

## Impact on Data Size

**gRPC/Protocol Buffers vs. Custom Serialization/JSON:**

- **Efficiency and Compactness:**  
  The gRPC method (which uses Protocol Buffers) produces very compact binary messages. For example, a `LoginRequest` is serialized into only 26 bytes, and a `UsernameRequest` (used for account deletion) is just 7 bytes. These sizes are comparable to the custom binary protocol (e.g., 26 bytes for login, 14 bytes for delete account) and are significantly smaller than their JSON-based counterparts (e.g., 65 bytes for login, 50 bytes for delete account).

- **Comparison of Results:**  
  - **LoginRequest:**  
    - gRPC: 26 bytes  
    - Custom: 26 bytes  
    - JSON: 65 bytes
  - **SendMessageRequest:**  
    - gRPC: 25 bytes  
    - Custom: 30 bytes  
    - JSON: 68 bytes
  - **ListAccountsRequest:**  
    - gRPC: 14 bytes  
    - Custom: 20 bytes  
    - JSON: 59 bytes
  - **ViewMessagesRequest:**  
    - gRPC: 9 bytes  
    - Custom: 17 bytes  
    - JSON: 56 bytes
  - **UsernameRequest (for DeleteAccount):**  
    - gRPC: 7 bytes  
    - Custom: 14 bytes  
    - JSON: 50 bytes

- **Conclusion:**  
  Using gRPC/Protobuf does not increase the size of the data passed—in fact, it tends to produce messages that are as small as or even smaller than the custom binary serialization. Moreover, it is much more efficient than JSON serialization. This efficiency is one of the key advantages of Protocol Buffers, especially in high-performance or bandwidth-constrained environments.

# 3/26/25:

# Replication

# Engineering Notebook: Persistent & Fault-Tolerant Chat System

## Project Overview

This notebook documents the design and implementation decisions made while developing a persistent and fault-tolerant chat system. Building upon a previous gRPC chat application implementation, this version introduces:

1. **Persistence**: Server state is preserved across shutdowns and restarts
2. **Fault Tolerance**: The system can tolerate up to two simultaneous node failures

## Key Design Decisions

### 1. Persistence Mechanism

The persistence layer was implemented in `common/persistence.py` using Python's `pickle` module to serialize and deserialize application state. This approach was chosen for its simplicity and ability to handle complex Python objects.

#### State Structure

The persisted state contains:
- User accounts and associated data
- Message queues for each user
- Replication log to track applied updates

```python
# Example state structure
state = {
    "users": {},             # Dictionary of User objects
    "message_queues": {},    # Message queues by username
    "replication_log": set() # Set of applied update IDs
}
```

#### File Naming Strategy

Each server instance uses a unique state file name based on hostname and port:

```python
def get_state_file(port):
    hostname = socket.gethostname()
    return f"server_state_{hostname}_{port}.pkl"
```

This ensures that multiple server instances running on the same machine don't conflict.

#### Persistence Triggers

State is persisted to disk after every significant operation:
- Account creation/deletion
- Message sending
- Message deletion
- Replication of operations from other nodes

We considered event-based persistence (saving only on certain intervals) but opted for immediate persistence after operations to minimize data loss in case of failures.

### 2. Replication Strategy

After evaluating several replication approaches (active replication, chain replication), we chose a primary-backup replication model for its simplicity and strong consistency guarantees.

#### Primary-Backup Model

In this model:
- One server acts as the primary (leader)
- All write operations go through the leader
- The leader propagates changes to all backup nodes
- Read operations can be served by any node

#### Update Propagation

Each update operation is assigned a unique ID using UUID:

```python
update_id = str(uuid.uuid4())
```

This ID is included in the replication request to prevent duplicate application of updates:

```python
def replicate_update(self, operation, data, update_id):
    req = message_service_pb2.ReplicationRequest(
        operation=operation,
        data=data,
        update_id=update_id
    )
    # Send to all replicas...
```

#### Update Reception

When a node receives a replication request, it checks if the update has already been applied:

```python
def ReplicateOperation(self, request, context):
    update_id = request.update_id
    with self.user_lock:
        if update_id in self.replication_log:
            return message_service_pb2.StatusResponse(
                success=True,
                message="Update already applied"
            )
        # Apply the update...
```

This idempotency ensures that operations are applied exactly once, even if replication requests are retried.

### 3. Leader Election

The leader election mechanism was designed to be simple yet effective for our fault tolerance requirements.

#### Election Approach

We implemented a heartbeat-based leader detection with a deterministic tie-breaking rule:
- Each node periodically pings the current leader
- If the leader becomes unreachable, an election is triggered
- The node with the lexicographically smallest address becomes the new leader

```python
def elect_leader(self):
    active_nodes = [self.my_address]
    # Ping all replicas...
    new_leader = min(active_nodes)
    self.current_leader = new_leader
    self.is_leader = (self.my_address == new_leader)
```

#### Leader Monitoring

A background thread continually monitors the leader's health:

```python
def run_leader_election_loop(self):
    while True:
        time.sleep(5)  # Check every 5 seconds
        if self.current_leader == self.my_address:
            # I am the leader
            continue
        else:
            try:
                # Try to ping the leader
                channel = grpc.insecure_channel(self.current_leader)
                stub = message_service_pb2_grpc.ChatServiceStub(channel)
                stub.Ping(req, timeout=2)
                channel.close()
            except Exception:
                # Leader unreachable, trigger election
                self.elect_leader()
```

We considered implementing more sophisticated consensus algorithms like Raft or Paxos but chose this simpler approach since our requirements only specify crash/failstop failures rather than Byzantine failures.

### 4. State Synchronization

When a new node joins or a failed node recovers, it needs to synchronize its state with the current system state.

#### Full State Transfer

We implemented a full state transfer mechanism where a node can request the complete state from the current leader:

```python
def resync_state(self):
    try:
        channel = grpc.insecure_channel(self.current_leader)
        stub = message_service_pb2_grpc.ChatServiceStub(channel)
        req = message_service_pb2.SyncStateRequest()
        resp = stub.SyncState(req, timeout=5)
        # Process and apply the received state...
    except Exception as e:
        print(f"Failed to resync state: {e}")
```

The leader serializes its current state as JSON and sends it to the requesting node:

```python
def SyncState(self, request, context):
    with self.user_lock:
        # Convert state to JSON...
    return message_service_pb2.SyncStateResponse(state_json=state_json)
```

We chose JSON serialization for the sync operation (rather than pickle) to ensure compatibility across different Python versions that might be running on different nodes.

#### Serialization Challenges

One challenge was handling non-serializable objects like Python's `Queue`. Our solution was to convert queues to lists for serialization:

```python
# Convert Queue objects to lists for serialization
mq = {username: list(q.queue) for username, q in self.message_queues.items()}
```

And then reconstruct them at the receiving end:

```python
# Reconstruct Queue objects from lists
for username, messages in mq_data.items():
    q = Queue()
    for msg in messages:
        q.put(msg)
    self.message_queues[username] = q
```

### 5. Concurrency Control

To ensure thread safety in a multi-threaded environment, we implemented proper locking mechanisms.

#### Locking Strategy

A single lock protects all shared state:

```python
self.user_lock = threading.Lock()
```

This lock is acquired before any operation that modifies the shared state:

```python
with self.user_lock:
    # Modify shared state...
```

While this approach may limit concurrency, it simplifies reasoning about the system and prevents subtle race conditions.

#### Thread Separation

The server uses multiple threads for different operations:
- Main thread for handling RPCs
- Background thread for leader election
- Stream threads for real-time message delivery

## Implementation Details

### Protocol Buffer Enhancements

We extended the existing protocol buffer definition to support replication and leader election:

```protobuf
// Replication messages
message ReplicationRequest {
  string operation = 1;    // Operation type
  string data = 2;         // Operation data
  string update_id = 3;    // Unique identifier
}

// Leader election messages
message PingRequest {
  string dummy = 1;
}

message PingResponse {
  string message = 1;
  string sender_id = 2;
}

// State synchronization
message SyncStateRequest {
  // Empty for now
}

message SyncStateResponse {
  string state_json = 1;
}
```

These new message types support the distributed coordination required for fault tolerance.

### Handling User Messages

The message handling logic was enhanced to support both immediate delivery and queuing:

```python
def SendMessage(self, request, context):
    # ...
    if recipient in self.active_users:
        # Immediate delivery
        self.message_queues[recipient].put(
            message_service_pb2.MessageResponse(
                sender=sender,
                content=content,
                timestamp=timestamp
            )
        )
        self.users[recipient].add_read_message(full_message)
    else:
        # Queue for later delivery
        self.users[recipient].queue_message(full_message)
    # Replicate to other nodes...
```

This ensures messages are delivered in real-time to active users while being properly queued for offline users.

### Server Initialization

The server initialization process incorporates persistence and leader election:

```python
def __init__(self, port, replica_addresses=None):
    # Load persisted state
    state = load_state(self.my_port)
    self.users = state.get("users", {})
    # ...
    
    # Set up replication
    self.replica_addresses = replica_addresses if replica_addresses else []
    self.my_address = f"{socket.gethostname()}:{port}"
    
    # Leader election initialization
    self.current_leader = self.my_address
    self.is_leader = True
    
    # Start background threads
    threading.Thread(target=self.run_leader_election_loop, daemon=True).start()
    
    # State synchronization if not leader
    if not self.is_leader:
        self.resync_state()
```

## Testing and Validation

### Test Categories

We developed several categories of tests to validate the system:

1. **Unit Tests**:
   - Tests for individual components like persistence, user operations
   - Tests that mock dependencies for isolation

2. **Integration Tests**:
   - Tests that verify interaction between components
   - Tests for end-to-end message delivery

3. **Fault Tolerance Tests**:
   - Tests that simulate node failures
   - Tests for leader election and recovery
   - Tests for data consistency after failures

### Testing Challenges

#### State Verification

Verifying that state is correctly preserved and synchronized across nodes was challenging. Our approach was to:

1. Create a known initial state
2. Perform operations that modify the state
3. Simulate node failures
4. Verify that the state is correct after recovery

#### Leader Election Testing

Testing leader election required simulating network failures. We implemented this by:

1. Starting multiple server instances
2. Forcibly killing the leader process
3. Verifying that a new leader is elected
4. Verifying that operations continue to work with the new leader

## Challenges and Solutions

### Challenge 1: Ensuring Exactly-Once Semantics

**Problem**: Ensuring operations are applied exactly once, even with retries and node failures.

**Solution**: Implemented idempotent operations using unique update IDs. Each update is tracked in the replication log, and already-applied updates are detected and ignored.

### Challenge 2: Handling Queue Serialization

**Problem**: Python's Queue objects are not directly serializable.

**Solution**: Converted queues to lists for serialization and reconstructed them after deserialization. This required careful handling to ensure the queue state was preserved correctly.

### Challenge 3: Detecting Leader Failures

**Problem**: Quickly and accurately detecting when the leader has failed.

**Solution**: Implemented a heartbeat mechanism with timeouts. Nodes ping the leader periodically, and if the leader becomes unreachable, an election is triggered.

### Challenge 4: Managing Distributed State

**Problem**: Ensuring consistency across distributed nodes.

**Solution**: Used a primary-backup model where all write operations go through the leader. This simplified consistency management at the cost of some availability during leader transitions.

## Future Improvements

Based on the current implementation, several improvements could enhance the system:

1. **Incremental State Synchronization**: Instead of transferring the entire state, implement a log-based approach where only missing updates are transferred.

2. **Consensus Algorithm**: Replace the simple leader election with a more robust consensus algorithm like Raft to handle more complex failure scenarios.

3. **Client-Side Leader Discovery**: Allow clients to automatically discover and connect to the current leader instead of requiring manual configuration.

4. **Performance Optimizations**: Add batching, compression, and other optimizations to improve performance for large-scale deployments.

## Lessons Learned

This project provided valuable insights into distributed systems design:

1. **Simplicity vs. Robustness**: Simpler designs are easier to implement and debug, but may not handle all failure cases.

2. **State Management**: Proper state persistence and synchronization are crucial for fault tolerance.

3. **Testing Distributed Systems**: Testing distributed systems requires careful setup and validation of failure scenarios.

4. **Locking Discipline**: Consistent locking discipline is essential to prevent race conditions in multi-threaded environments.

