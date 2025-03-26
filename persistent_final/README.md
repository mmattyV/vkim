# Persistent & Fault-Tolerant Chat System

A distributed chat application with persistence and fault tolerance. This system can withstand up to two simultaneous node failures while maintaining consistency and data integrity.

## Features

- **Persistence**: System state is preserved across restarts
- **Fault Tolerance**: 2-fault tolerant with automatic recovery
- **Leader Election**: Automatic leader election when nodes fail
- **State Synchronization**: Seamless state recovery for new/restarted nodes

## System Architecture

The system follows a client-server architecture with multiple server replicas to achieve fault tolerance:

1. **Client**: Connects to the server for messaging operations
2. **Server**: Handles chat functionality and replicates state to other servers
3. **Persistence Layer**: Saves and loads state to/from disk
4. **Replication Mechanism**: Propagates changes to all replicas
5. **Leader Election**: Elects a leader among the server replicas for coordinating operations

## Prerequisites

- Python 3.6 or higher
- gRPC and Protobuf libraries

## Installation

1. Clone the repository:
   ```
   git clone https://github.com/yourusername/persistent-chat.git
   cd persistent-chat
   ```

2. Install dependencies:
   ```
   python setup.py
   ```

## Usage

### Starting the Servers


   ```
   python grpc_server.py --port 50051 --replicas "localhost:50052,localhost:50053"
   python grpc_server.py --port 50052 --replicas "localhost:50051,localhost:50053"
   python grpc_server.py --port 50053 --replicas "localhost:50051,localhost:50052”
   ```

For cross-machine deployment, use the actual hostnames instead of localhost.

### Starting the Client

Run the GUI client:
```
python grpc_gui.py --host localhost --port 50052 --replicas "localhost:50051,localhost:50053,localhost:50052"
```

## Testing

Run the test suite:
```
python -m unittest discover tests
```

## Demo Instructions

To demonstrate the system's capabilities:

1. **Start Multiple Servers**: Launch 3 server instances across different machines or ports
2. **Create User Accounts**: Create accounts and send messages using the client
3. **Demonstrate Persistence**: 
   - Stop and restart servers to show state is preserved
   - Verify that all messages are still available

4. **Demonstrate Fault Tolerance**:
   - Kill the leader node to trigger leader election
   - Show that the system continues to function with the new leader
   - Kill a second node to show 2-fault tolerance

5. **Show Recovery**: 
   - Restart a failed node 
   - Demonstrate state synchronization with the current leader

## File Structure

```
persistent_final/
├── client/            # Client implementation
├── common/            # Shared utilities 
├── protos/            # Protocol buffer definitions
├── server/            # Server implementation
└── tests/             # Unit and integration tests
```