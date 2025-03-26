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